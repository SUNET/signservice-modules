package se.sunet.edusign.harica.authn;

import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.signservice.authn.saml.AbstractSamlAuthenticationHandler;
import se.swedenconnect.signservice.authn.saml.config.SpUrlConfiguration;

/**
 * An SAML authentication handler for supporting the Harica model.
 */
public class HaricaSamlAuthenticationHandler extends AbstractSamlAuthenticationHandler {

  /**
   * Constructor.
   *
   * @param authnRequestGenerator the generator for creating authentication requests
   * @param responseProcessor the SAML response processor
   * @param metadataProvider the SAML metadata provider
   * @param entityDescriptorContainer the container for this SP's metadata
   * @param urlConfiguration the URL configuration
   */
  public HaricaSamlAuthenticationHandler(final AuthnRequestGenerator authnRequestGenerator,
      final ResponseProcessor responseProcessor,
      final MetadataProvider metadataProvider,
      final EntityDescriptorContainer entityDescriptorContainer,
      final SpUrlConfiguration urlConfiguration) {
    super(authnRequestGenerator, responseProcessor, metadataProvider, entityDescriptorContainer, urlConfiguration);
  }

  // TODO: Implement Harica specifics ...

}
