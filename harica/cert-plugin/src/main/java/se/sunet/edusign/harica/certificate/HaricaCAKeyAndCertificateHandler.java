package se.sunet.edusign.harica.certificate;

import java.security.KeyException;
import java.security.cert.CertificateException;
import java.util.Objects;

import javax.annotation.Nonnull;

import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.AbstractSignServiceHandler;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.harica.commons.SerializableCredentials;
import se.swedenconnect.signservice.protocol.SignRequestMessage;

/**
 * Provide the sign service credentials based on completed authentication and certificate issuance using the
 * Harica CA API.
 */
public class HaricaCAKeyAndCertificateHandler extends AbstractSignServiceHandler
  implements KeyAndCertificateHandler {

  /** Prefix for all context values that we store/retrieve. */
  public static final String PREFIX = "se.swedenconnect.signservice.harica";

  /** Key for storing the signer credentials data */
  public static final String SIGNER_CREDENTIAL_KEY = PREFIX + ".SignerCredentials";

  /**
   * Constructor for this Key and Certificate handler
   */
  public HaricaCAKeyAndCertificateHandler() {
  }

  @Override public void checkRequirements(@Nonnull SignRequestMessage signRequestMessage,
    @Nonnull SignServiceContext context) throws InvalidRequestException {

    SerializableCredentials serializableCredentials = context.get(SIGNER_CREDENTIAL_KEY);
    if (serializableCredentials == null) {
      throw new InvalidRequestException("No signer key is available");
    }
  }

  @Nonnull @Override public PkiCredential generateSigningCredential(@Nonnull SignRequestMessage signRequestMessage,
    @Nonnull IdentityAssertion identityAssertion, @Nonnull SignServiceContext context)
    throws KeyException, CertificateException {

    SerializableCredentials serializableCredentials = Objects.requireNonNull(context.get(SIGNER_CREDENTIAL_KEY),
      "Session stored signing credentials must not be null");

    if (serializableCredentials.getCertificate() == null) {
      throw new CertificateException("No signer certificate is available");
    }
    if (serializableCredentials.getCertificateChain().isEmpty()) {
      throw new CertificateException("No signer certificate chain is available");
    }
    PkiCredential pkiCredential = new BasicCredential(serializableCredentials.getCertificateChain(),
      serializableCredentials.getPrivateKey());
    serializableCredentials.destroy();
    context.remove(SIGNER_CREDENTIAL_KEY);
    return pkiCredential;
  }
}
