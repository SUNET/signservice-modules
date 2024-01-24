package se.sunet.edusign.certificate;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.ca.cmc.api.client.CMCClient;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.signservice.authn.AuthnContextIdentifier;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMappingData;
import se.swedenconnect.signservice.certificate.cmc.CMCKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.cmc.CertificateRequestFormat;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.protocol.SignRequestMessage;

/**
 * Custom implementation of {@link CMCKeyAndCertificateHandler} that places a custom eduSign specific authentication
 * context class reference URI in the certificate.
 *
 * @author Martin Lindström
 */
public class EduSignCMCKeyAndCertificateHandler extends CMCKeyAndCertificateHandler {

  private final static String CUSTOM_AUTHN_CONTEXT_URI_KEY = "eduSign.CUSTOM_AUTHN_CONTEXT";

  /**
   * Constructor.
   *
   * @param keyProvider a {@link PkiCredentialContainer} acting as the source of generated signing keys
   * @param algorithmKeyTypes a map of the selected key type for each supported algorithm
   * @param attributeMapper the attribute mapper
   * @param algorithmRegistry algorithm registry
   * @param cmcClient CMC client used to issue certificates using CMC
   * @param certificateRequestFormat the certificate request format (defaults to
   *          {@link CertificateRequestFormat#pkcs10}).
   */
  public EduSignCMCKeyAndCertificateHandler(
      @Nonnull final PkiCredentialContainer keyProvider,
      @Nullable final Map<String, String> algorithmKeyTypes,
      @Nonnull final AttributeMapper attributeMapper,
      @Nullable final AlgorithmRegistry algorithmRegistry,
      @Nonnull final CMCClient cmcClient,
      @Nullable final CertificateRequestFormat certificateRequestFormat) {
    super(keyProvider, algorithmKeyTypes, attributeMapper, algorithmRegistry, cmcClient, certificateRequestFormat);
  }

  /**
   * Checks to see if there is a eduSign custom authentication context URI in the SignService context, and if so,
   * uses this when creating the certificate. Otherwise "normal" execution proceeds.
   */
  @Override
  protected List<X509Certificate> issueSigningCertificateChain(
      @Nonnull final PkiCredential signingKeyPair,
      @Nonnull final SignRequestMessage signRequest,
      @Nonnull final IdentityAssertion assertion,
      @Nonnull final List<AttributeMappingData> certAttributes,
      @Nullable final String certificateProfile,
      @Nonnull final SignServiceContext context) throws CertificateException {

    final String customAuthnContextUri = context.get(CUSTOM_AUTHN_CONTEXT_URI_KEY);
    final IdentityAssertion idAssertion;
    if (customAuthnContextUri != null) {
      idAssertion = createCustomAssertion(assertion, customAuthnContextUri);
      context.remove(CUSTOM_AUTHN_CONTEXT_URI_KEY);
    }
    else {
      idAssertion = assertion;
    }
    return super.issueSigningCertificateChain(
        signingKeyPair, signRequest, idAssertion, certAttributes, certificateProfile, context);
  }

  private static IdentityAssertion createCustomAssertion(final IdentityAssertion assertion, final String authnContextUri) {
    return new IdentityAssertion() {

      private static final long serialVersionUID = 8443025329676364296L;

      @Override
      public String getScheme() {
        return assertion.getScheme();
      }

      @Override
      public String getIdentifier() {
        return assertion.getIdentifier();
      }

      @Override
      public String getIssuer() {
        return assertion.getIssuer();
      }

      @Override
      public Instant getIssuanceInstant() {
        return assertion.getIssuanceInstant();
      }

      @Override
      public Instant getAuthnInstant() {
        return assertion.getAuthnInstant();
      }

      @Override
      public AuthnContextIdentifier getAuthnContext() {
        return new SimpleAuthnContextIdentifier(authnContextUri);
      }

      @Override
      public List<IdentityAttribute<?>> getIdentityAttributes() {
        return assertion.getIdentityAttributes();
      }

      @Override
      public byte[] getEncodedAssertion() {
        return assertion.getEncodedAssertion();
      }

    };
  }

}
