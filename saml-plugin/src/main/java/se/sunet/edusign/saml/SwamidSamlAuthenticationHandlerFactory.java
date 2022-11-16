package se.sunet.edusign.saml;

import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectDecrypter;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.authn.saml.config.SamlAuthenticationHandlerConfiguration;
import se.swedenconnect.signservice.authn.saml.config.SamlAuthenticationHandlerFactory;
import se.swedenconnect.signservice.core.config.BeanLoader;

/**
 * A factory for creating {@link SwamidSamlAuthenticationHandler} instances.
 */
public class SwamidSamlAuthenticationHandlerFactory extends SamlAuthenticationHandlerFactory {

  /** The SAML type for the Swamid federation. */
  public static final String SAML_TYPE_SWAMID = "swamid";

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

  /**
   * Work-around: Will be fixed in next version of signservice code.
   */
  @Override
  protected ResponseProcessor createResponseProcessor(final SamlAuthenticationHandlerConfiguration config,
      final SAMLObjectDecrypter decrypter, final MessageReplayChecker messageReplayChecker,
      final MetadataProvider metadataProvider) {

    if (SAML_TYPE_SWAMID.equals(config.getSamlType())) {
      config.setSamlType(SamlAuthenticationHandlerConfiguration.SAML_TYPE_DEFAULT);
      final ResponseProcessor p =
          super.createResponseProcessor(config, decrypter, messageReplayChecker, metadataProvider);
      config.setSamlType(SAML_TYPE_SWAMID);
      return p;
    }
    else {
      return super.createResponseProcessor(config, decrypter, messageReplayChecker, metadataProvider);
    }
  }

  /**
   * Work-around: Will be fixed in next version of signservice code.
   */
  @Override
  protected AuthnRequestGenerator createAuthnRequestGenerator(final SamlAuthenticationHandlerConfiguration config,
      final BeanLoader beanLoader, final MetadataProvider metadataProvider, final EntityDescriptor entityDescriptor) {

    if (SAML_TYPE_SWAMID.equals(config.getSamlType())) {
      config.setSamlType(SamlAuthenticationHandlerConfiguration.SAML_TYPE_DEFAULT);
      final AuthnRequestGenerator g =
          super.createAuthnRequestGenerator(config, beanLoader, metadataProvider, entityDescriptor);
      config.setSamlType(SAML_TYPE_SWAMID);
      return g;
    }
    else {
      return super.createAuthnRequestGenerator(config, beanLoader, metadataProvider, entityDescriptor);
    }
  }

}
