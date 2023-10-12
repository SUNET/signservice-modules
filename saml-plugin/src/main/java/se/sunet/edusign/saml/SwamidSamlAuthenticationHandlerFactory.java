package se.sunet.edusign.saml;

import java.util.Optional;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.opensaml.saml2.response.validation.ResponseValidationSettings;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectDecrypter;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.authn.saml.config.SamlAuthenticationHandlerConfiguration;
import se.swedenconnect.signservice.authn.saml.config.SamlAuthenticationHandlerFactory;

/**
 * A factory for creating {@link SwamidSamlAuthenticationHandler} instances.
 */
public class SwamidSamlAuthenticationHandlerFactory extends SamlAuthenticationHandlerFactory {

  /** The SAML type for the Swamid federation. */
  public static final String SAML_TYPE_SWAMID = "swamid";

  /**
   * Supports the Swamid federation ...
   */
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

  /**
   * Creates the Swamid special response processor.
   */
  @Override
  protected ResponseProcessor createResponseProcessor(final SamlAuthenticationHandlerConfiguration config,
      final SAMLObjectDecrypter decrypter, final MessageReplayChecker messageReplayChecker,
      final MetadataProvider metadataProvider) {

    if (SAML_TYPE_SWAMID.equals(config.getSamlType())) {
      final SwamidResponseProcessor processor = new SwamidResponseProcessor();
      processor.setDecrypter(decrypter);
      processor.setMessageReplayChecker(messageReplayChecker);
      processor.setMetadataResolver(metadataProvider.getMetadataResolver());
      processor.setRequireEncryptedAssertions(Optional.ofNullable(config.getRequireEncryptedAssertions()).orElse(true));

      final ResponseValidationSettings validationSettings = new ResponseValidationSettings();
      validationSettings.setAllowedClockSkew(this.getValidationConfig().getAllowedClockSkew());
      validationSettings.setMaxAgeResponse(this.getValidationConfig().getMaxMessageAge());
      if (config.getRequireSignedAssertions() != null) {
        validationSettings.setRequireSignedAssertions(config.getRequireSignedAssertions().booleanValue());
      }
      processor.setResponseValidationSettings(validationSettings);
      try {
        processor.initialize();
      }
      catch (final ComponentInitializationException e) {
        throw new IllegalArgumentException("Failed to initialize SAML response processor - " + e.getMessage(), e);
      }
      return processor;
    }
    else {
      return super.createResponseProcessor(config, decrypter, messageReplayChecker, metadataProvider);
    }
  }

}
