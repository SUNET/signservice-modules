package se.sunet.edusign.harica.authn;

import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.authn.saml.config.SamlAuthenticationHandlerConfiguration;
import se.swedenconnect.signservice.authn.saml.config.SamlAuthenticationHandlerFactory;

/**
 * A factory for creating {@link HaricaSamlAuthenticationHandler} instances.
 */
public class HaricaSamlAuthenticationHandlerFactory extends SamlAuthenticationHandlerFactory {

  /** The SAML type for the Harica federation. */
  public static final String SAML_TYPE_HARICA = "harica";

  /**
   * Supports the "harica" SAML type also.
   */
  @Override
  protected void assertSamlType(final String type) throws IllegalArgumentException {
    if (SAML_TYPE_HARICA.equals(type)) {
      return;
    }
    else {
      super.assertSamlType(type);
    }
  }

  /**
   * Supports the harica SAML type.
   */
  @Override
  protected AuthenticationHandler createHandler(final SamlAuthenticationHandlerConfiguration config,
      final MetadataProvider metadataProvider, final EntityDescriptorContainer entityDescriptorContainer,
      final ResponseProcessor responseProcessor, final AuthnRequestGenerator authnRequestGenerator,
      final String preferredRequestBinding) {

    if (SAML_TYPE_HARICA.equals(config.getSamlType())) {
      final HaricaSamlAuthenticationHandler handler =
          new HaricaSamlAuthenticationHandler(authnRequestGenerator, responseProcessor, metadataProvider,
              entityDescriptorContainer, config.getSpPaths());
      handler.setPreferredBindingUri(preferredRequestBinding);
      return handler;
    }
    else {
      return super.createHandler(config, metadataProvider, entityDescriptorContainer, responseProcessor,
          authnRequestGenerator, preferredRequestBinding);
    }
  }

  // TODO: Implement Harica specific configuration ...

}
