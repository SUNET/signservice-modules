package se.sunet.edusign.harica.authn.service;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.cmc.CertificationRequest;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import lombok.RequiredArgsConstructor;
import se.sunet.edusign.harica.authn.service.dto.CreateUserDetails;
import se.swedenconnect.ca.cmc.api.CMCCertificateModelBuilder;
import se.swedenconnect.ca.cmc.api.CMCMessageException;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.engine.ca.attribute.AttributeValueEncoder;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.data.AttributeMappingBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.data.QcStatementsBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.data.SAMLAuthContextBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.AbstractCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.cert.extensions.QCStatements;
import se.swedenconnect.cert.extensions.data.saci.AttributeMapping;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * CertificateRequestFactory bean
 */
@RequiredArgsConstructor
public class CertificateRequestFactory {

  private final X509CertificateHolder issuerCertificate;
  private final List<String> crlDpUrls;
  private final String ocspUrl;

  public String generatePKCS10Request(CreateUserDetails userDetails, PkiCredential pkiCredential, SignatureAlgorithm algorithm)
    throws CertificateIssuanceException {

    try {
      final ContentSigner p10Signer = new JcaContentSignerBuilder(algorithm.getJcaName())
        .build(pkiCredential.getPrivateKey());
      CertificateModel certificateModel = getCertificateModel(userDetails, pkiCredential.getPublicKey(), algorithm.getUri());
      final CertificationRequest certificationRequest = CMCUtils.getCertificationRequest(
        certificateModel, p10Signer,
        new AttributeValueEncoder());

      PemObject pemObject = new PemObject(PEMParser.TYPE_CERTIFICATE_REQUEST, certificationRequest.getEncoded());
      try (
        StringWriter str = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(str)
      ) {
        pemWriter.writeObject(pemObject);
        IOUtils.closeQuietly(pemWriter);
        return str.toString();
      }

    }
    catch (IOException | CMCMessageException | OperatorCreationException e) {
      throw new CertificateIssuanceException(e);
    }
  }

  public CertificateModel getCertificateModel(CreateUserDetails userDetails, PublicKey publicKey, String algorithm)
    throws CertificateIssuanceException {
    // Get certificate subject name model.
    final CertNameModel<?> certificateNameModel = this.createCertificateNameModel(userDetails);

    // Get the certificate model builder.
    final AbstractCertificateModelBuilder<? extends AbstractCertificateModelBuilder<?>> certificateModelBuilder =
      this.createCertificateModelBuilder(certificateNameModel, publicKey, issuerCertificate, algorithm, crlDpUrls,
        ocspUrl);

    // Add QC declarations.
    certificateModelBuilder.qcStatements(QcStatementsBuilder.instance()
      .qualifiedCertificate(true)
      .qcTypes(List.of(QCStatements.QC_TYPE_ELECTRONIC_SIGNATURE))
      .qscd(true)
      .build());

    // Add the AuthContextExtension.
    certificateModelBuilder.authenticationContext(SAMLAuthContextBuilder.instance()
      .serviceID("Test-signservice")
      .assertionRef("id_" + new BigInteger(64, new Random()).toString(16))
      .authnContextClassRef("http://eidas.europa.eu/LoA/substantial")
      .authenticationInstant(new Date())
      .identityProvider("https://example.com/idp")
      .attributeMappings(this.getAuthContextExtAttributeMappings(userDetails))
      .build());

    // Add Subject alternative names if present.

    return certificateModelBuilder.build();
  }

  private List<AttributeMapping> getAuthContextExtAttributeMappings(CreateUserDetails userDetails) {

    final List<AttributeMapping> extAttrMappingList = new ArrayList<>();
    extAttrMappingList.add(getAttributeMapping(
      CertAttributes.SERIALNUMBER.getId(),
      AttributeMapping.Type.rdn,
      "urn:oid:1.2.752.201.3.7",
      userDetails.getUniqueIdentifier()
    ));
    if (userDetails.getSurname() != null) {
      extAttrMappingList.add(getAttributeMapping(
        CertAttributes.SURNAME.getId(),
        AttributeMapping.Type.rdn,
        "urn:oid:" + CertAttributes.SURNAME.getId(),
        userDetails.getSurname()
      ));
    }
    if (userDetails.getGivenName() != null) {
      extAttrMappingList.add(getAttributeMapping(
        CertAttributes.GIVENNAME.getId(),
        AttributeMapping.Type.rdn,
        "urn:oid:" + CertAttributes.GIVENNAME.getId(),
        userDetails.getGivenName()
      ));
    }
    if (userDetails.getEmail() != null) {
      extAttrMappingList.add(getAttributeMapping(
        CertAttributes.EmailAddress.getId(),
        AttributeMapping.Type.rdn,
        "urn:oid:" + CertAttributes.EmailAddress.getId(),
        userDetails.getSurname()
      ));
    }
    return extAttrMappingList;
  }

  private AttributeMapping getAttributeMapping(String ref, AttributeMapping.Type type, String name, String val) {
    return AttributeMappingBuilder.instance()
      .ref(ref)
      .type(type)
      .name(name)
      .attributeStringValue(val)
      .build();
  }

  private AbstractCertificateModelBuilder<? extends AbstractCertificateModelBuilder<?>> createCertificateModelBuilder(
    CertNameModel<?> subject, PublicKey subjectPublicKey, X509CertificateHolder caIssuerCert, String algorithm,
    List<String> crlDpUrls, String ocspUrl) {

    final CMCCertificateModelBuilder certModelBuilder =
      CMCCertificateModelBuilder.getInstance(subjectPublicKey, caIssuerCert,
        algorithm);

    if (crlDpUrls != null && !crlDpUrls.isEmpty()) {
      certModelBuilder.crlDistributionPoints(crlDpUrls);
    }
    if (ocspUrl != null) {
      certModelBuilder.ocspServiceUrl(ocspUrl);
    }
    certModelBuilder.subject(subject);
    return certModelBuilder;
  }

  private CertNameModel<?> createCertificateNameModel(CreateUserDetails userDetails) {
    final List<AttributeTypeAndValueModel> attributeList = new ArrayList<>();

    attributeList.add(AttributeTypeAndValueModel.builder()
      .attributeType(CertAttributes.SERIALNUMBER)
      .value(userDetails.getUniqueIdentifier())
      .build());
    if (userDetails.getSurname() != null) {
      attributeList.add(AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.SURNAME)
        .value(userDetails.getSurname())
        .build());
    }
    if (userDetails.getGivenName() != null) {
      attributeList.add(AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.GIVENNAME)
        .value(userDetails.getGivenName())
        .build());
    }
    if (userDetails.getEmail() != null) {
      attributeList.add(AttributeTypeAndValueModel.builder()
        .attributeType(CertAttributes.EmailAddress)
        .value(userDetails.getEmail())
        .build());
    }

    return new ExplicitCertNameModel(attributeList);
  }
}
