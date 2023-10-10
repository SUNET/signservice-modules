package se.sunet.edusign.harica.authn.result;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.style.BCStyle;

import se.swedenconnect.signservice.authn.AuthenticationResult;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.authn.impl.DefaultIdentityAssertion;
import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;

/**
 * Authentication result from CA Authentication
 */
public class CAAuthResult implements AuthenticationResult {

  private static final long serialVersionUID = 4494910561079879178L;

  private final IdentityAssertion identityAssertion;

  private boolean displayedSignMessage;

  /**
   * This constructor instantiates the CA Authentication result by creating an IdentityAssertion object from an issued
   * certificate and some additional parameters
   *
   * @param certificate The issued certificate
   * @param loa the level of assurance to be declared as the result LoA
   * @param uidAttribute the attribute type that will be declared as the source of the primary ID attribute value
   * @param authServiceId the ID of the authentication service that will be declared as the issuer of the assertion
   * @param displayedSignMessage true if a sign message was displayed to the user
   * @throws CertificateEncodingException error parsing certificate data
   * @throws IOException invalid input
   */
  public CAAuthResult(X509Certificate certificate, String loa, String uidAttribute, String authServiceId,
      boolean displayedSignMessage)
      throws CertificateEncodingException, IOException {
    this.displayedSignMessage = displayedSignMessage;
    this.identityAssertion = getAssertionFromCert(certificate, loa, uidAttribute, authServiceId);
  }

  /**
   * Get the {@link IdentityAssertion} object of the CA Authentication result
   *
   * @return {@link IdentityAssertion}
   */
  @Override
  public IdentityAssertion getAssertion() {
    return this.identityAssertion;
  }

  /**
   * Test if the sign message was displayed. This always returns false as
   *
   * @return
   */
  @Override
  public boolean signMessageDisplayed() {
    return displayedSignMessage;
  }

  /**
   * Extract an identity assertion object from a certificate
   *
   * @return IdentityAssertion
   */
  private IdentityAssertion getAssertionFromCert(X509Certificate certificate, String loa, String uidAttribute,
      String authServiceId)
      throws CertificateEncodingException, IOException {

    DefaultIdentityAssertion assertion = new DefaultIdentityAssertion();
    assertion.setScheme("PKI");
    assertion.setIdentifier(certificate.getSerialNumber().toString(16));
    assertion.setEncodedAssertion(certificate.getEncoded());
    assertion.setIssuer(authServiceId);
    assertion.setAuthnContext(new SimpleAuthnContextIdentifier(loa));
    assertion.setAuthnInstant(Instant.now());
    assertion.setIdentityAttributes(getAttributes(certificate, uidAttribute));

    return assertion;
  }

  /**
   * This is a simple implementation of extracting assertion result from an issued cert. A full implementation will use
   * the AuthContext extension and use its attribute mapping to locate the origin attribute names.
   */
  private List<IdentityAttribute<?>> getAttributes(X509Certificate certificate, String uidAttribute)
      throws IOException {

    List<IdentityAttribute<?>> assertionAttributes = new ArrayList<>();
    List<SubjectAttributeInfo> attributeInfoList = getAttributeInfoList(certificate.getSubjectX500Principal());

    addAttribute(BCStyle.SERIALNUMBER, uidAttribute,
        "personIdentifier", attributeInfoList, assertionAttributes);
    addAttribute(BCStyle.SURNAME, "urn:oid:2.5.4.4",
        "surname", attributeInfoList, assertionAttributes);
    addAttribute(BCStyle.GIVENNAME, "urn:oid:2.5.4.42",
        "givenName", attributeInfoList, assertionAttributes);
    addAttribute(BCStyle.EmailAddress, "urn:oid:0.9.2342.19200300.100.1.3",
        "email", attributeInfoList, assertionAttributes);
    addAttribute(BCStyle.CN, "urn:oid:2.16.840.1.113730.3.1.241",
        "displayName", attributeInfoList, assertionAttributes);
    addAttribute(BCStyle.C, "urn:oid:2.5.4.6", "country", attributeInfoList, assertionAttributes);
    return assertionAttributes;
  }

  private void addAttribute(ASN1ObjectIdentifier certAttr, String assertionAttr, String friendlyName,
      List<SubjectAttributeInfo> certAttrList, List<IdentityAttribute<?>> assertionAttributes) {

    Optional<SubjectAttributeInfo> certAttrOptional = certAttrList.stream()
        .filter(subjectAttributeInfo -> subjectAttributeInfo.getOid().equals(certAttr))
        .findFirst();
    certAttrOptional.ifPresent(subjectAttributeInfo -> assertionAttributes.add(
        new StringSamlIdentityAttribute(assertionAttr, friendlyName, subjectAttributeInfo.getValue())));
  }

  public static List<SubjectAttributeInfo> getAttributeInfoList(X500Principal name) throws IOException {
    List<SubjectAttributeInfo> attrInfoList = new ArrayList<>();
    try (ASN1InputStream ain = new ASN1InputStream(name.getEncoded())) {
      ASN1Sequence nameSeq = ASN1Sequence.getInstance(ain.readObject());

      for (ASN1Encodable asn1Encodable : nameSeq) {
        ASN1Set rdnSet = (ASN1Set) asn1Encodable;
        for (ASN1Encodable encodable : rdnSet) {
          ASN1Sequence rdnSeq = (ASN1Sequence) encodable;
          ASN1ObjectIdentifier rdnOid = (ASN1ObjectIdentifier) rdnSeq.getObjectAt(0);
          // String oidStr = rdnOid.getId();
          ASN1Encodable rdnVal = rdnSeq.getObjectAt(1);
          String rdnValStr = getStringValue(rdnVal);
          attrInfoList.add(new SubjectAttributeInfo(rdnOid, rdnValStr));
        }
      }
    }
    return attrInfoList;
  }

  private static String getStringValue(ASN1Encodable rdnVal) {
    if (rdnVal instanceof DERUTF8String) {
      DERUTF8String utf8Str = (DERUTF8String) rdnVal;
      return utf8Str.getString();
    }
    if (rdnVal instanceof DERPrintableString) {
      DERPrintableString str = (DERPrintableString) rdnVal;
      return str.getString();
    }
    return rdnVal.toString();
  }
}
