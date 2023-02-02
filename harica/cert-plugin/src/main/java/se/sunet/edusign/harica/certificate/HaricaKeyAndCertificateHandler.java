package se.sunet.edusign.harica.certificate;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMappingData;
import se.swedenconnect.signservice.certificate.base.AbstractKeyAndCertificateHandler;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;

/**
 * A {@link KeyAndCertificateHandler} supporting the Harica model.
 */
public class HaricaKeyAndCertificateHandler extends AbstractKeyAndCertificateHandler {

  public HaricaKeyAndCertificateHandler(final PkiCredentialContainer keyProvider,
      final Map<String, String> algorithmKeyTypes, final AttributeMapper attributeMapper,
      final AlgorithmRegistry algorithmRegistry) {
    super(keyProvider, algorithmKeyTypes, attributeMapper, algorithmRegistry);
  }

  /** {@inheritDoc} */
  @Override
  protected List<X509Certificate> issueSigningCertificateChain(final PkiCredential signingKeyPair,
      final SignRequestMessage signRequest, final IdentityAssertion assertion,
      final List<AttributeMappingData> certAttributes,
      final String certificateProfile, final SignServiceContext context) throws CertificateException {

    // TODO
    return null;
  }

  /** {@inheritDoc} */
  @Override
  protected void assertCertificateProfileSupported(final String certificateProfile) throws InvalidRequestException {
    // TODO
  }

}
