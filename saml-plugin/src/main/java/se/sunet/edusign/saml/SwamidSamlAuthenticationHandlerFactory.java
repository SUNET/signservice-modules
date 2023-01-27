package se.sunet.edusign.saml;

import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.authn.saml.config.SamlAuthenticationHandlerConfiguration;
import se.swedenconnect.signservice.authn.saml.config.SamlAuthenticationHandlerFactory;

/**
 * A factory for creating {@link SwamidSamlAuthenticationHandler} instances.
 */
public class SwamidSamlAuthenticationHandlerFactory extends SamlAuthenticationHandlerFactory {

  /** The SAML type for the Swamid federation. */
  public static final String SAML_TYPE_SWAMID = "swamid";



  @Override
  protected void assertSamlType(final String type) throws IllegalArgumentException {
    if (SAML_TYPE_SWAMID.equals(type)) {
      return;
    }
    else {
      super.assertSamlType(type);
    }
  }



  /**
   * Supports the swamid SAML type.
   */
  @Override
  protected AuthenticationHandler createHandler(final SamlAuthenticationHandlerConfiguration config,
      final MetadataProvider metadataProvider, final EntityDescriptorContainer entityDescriptorContainer,
      final ResponseProcessor responseProcessor, final AuthnRequestGenerator authnRequestGenerator,
      final String preferredRequestBinding) {

    if (SAML_TYPE_SWAMID.equals(config.getSamlType())) {
      final SwamidSamlAuthenticationHandler handler =
          new SwamidSamlAuthenticationHandler(authnRequestGenerator, responseProcessor, metadataProvider,
              entityDescriptorContainer, config.getSpPaths());
      handler.setPreferredBindingUri(preferredRequestBinding);
      return handler;
    }
    else {
      return super.createHandler(config, metadataProvider, entityDescriptorContainer, responseProcessor,
          authnRequestGenerator, preferredRequestBinding);
    }
  }

}