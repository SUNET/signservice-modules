package se.sunet.edusign.saml;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.signservice.authn.AuthenticationErrorCode;
import se.swedenconnect.signservice.authn.AuthnContextIdentifier;
import se.swedenconnect.signservice.authn.UserAuthenticationException;
import se.swedenconnect.signservice.authn.saml.AbstractSamlAuthenticationHandler;
import se.swedenconnect.signservice.authn.saml.config.SpUrlConfiguration;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;
import se.swedenconnect.signservice.core.http.HttpUserRequest;
import se.swedenconnect.signservice.protocol.msg.AuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.SignMessage;

/**
 * Customizations of the SignService default SAML authentication handler to fit Swamid.
 */
@Slf4j
public class SwamidSamlAuthenticationHandler extends AbstractSamlAuthenticationHandler {

  /** Key for storing the requested authentication context. */
  public static final String REQUESTED_AUTHN_CONTEXT_KEY = AbstractSamlAuthenticationHandler.PREFIX + ".ReqAuthnCtx";

  /** The name for the eduPersonAssurance attribute. */
  private static final String EDU_PERSON_ASSURANCE_NAME = "urn:oid:1.3.6.1.4.1.5923.1.1.1.11";

  /**
   * Constructor.
   *
   * @param authnRequestGenerator the generator for creating authentication requests
   * @param responseProcessor the SAML response processor
   * @param metadataProvider the SAML metadata provider
   * @param entityDescriptorContainer the container for this SP's metadata
   * @param urlConfiguration the URL configuration
   */
  public SwamidSamlAuthenticationHandler(final AuthnRequestGenerator authnRequestGenerator,
      final ResponseProcessor responseProcessor, final MetadataProvider metadataProvider,
      final EntityDescriptorContainer entityDescriptorContainer, final SpUrlConfiguration urlConfiguration) {
    super(authnRequestGenerator, responseProcessor, metadataProvider, entityDescriptorContainer, urlConfiguration);
  }

  /**
   * Implements special handling of eduPersonAssurance ...
   */
  @Override
  protected void assertAttributes(final AuthnRequirements authnRequirements,
      final List<IdentityAttribute<?>> issuedAttributes,
      final SignServiceContext context) throws UserAuthenticationException {

    final IdentityAttribute<?> eduPersonAssuranceReq = authnRequirements.getRequestedSignerAttributes().stream()
        .filter(a -> EDU_PERSON_ASSURANCE_NAME.equals(a.getIdentifier()))
        .findFirst()
        .orElse(null);
    if (eduPersonAssuranceReq != null) {
      final IdentityAttribute<?> eduPersonAssurance = issuedAttributes.stream()
          .filter(a -> EDU_PERSON_ASSURANCE_NAME.equals(a.getIdentifier()))
          .findFirst()
          .orElse(null);
      if (eduPersonAssurance != null) {
        for (final Object value : eduPersonAssuranceReq.getValues()) {
          if (eduPersonAssurance.getValues().stream().filter(v -> Objects.equals(v, value)).findAny().isPresent()) {
            // Replace the multi-valued eduPersonAssurance attribute with a single-valued version containing only
            // the value that was requested.
            //
            final IdentityAttribute<?> updatedEduPersonAssurance =
                new StringSamlIdentityAttribute(EDU_PERSON_ASSURANCE_NAME, eduPersonAssurance.getFriendlyName(),
                    (String) value);
            issuedAttributes.removeIf(a -> EDU_PERSON_ASSURANCE_NAME.equals(a.getIdentifier()));
            issuedAttributes.add(updatedEduPersonAssurance);

            return;
          }
        }
        // else, let the super implementation fail
      }
      // else, let the super implementation fail ...
    }

    super.assertAttributes(authnRequirements, issuedAttributes, context);
  }

  /**
   * Creates an {@link AuthnRequestGeneratorContext} object that is to be used by the configured
   * {@link AuthnRequestGenerator}.
   * <p>
   * This is a customization of the default implementation where we make sure to not include a RequestedAuthnContext
   * element in the request. The reason for this is that Swamid uses an odd solution where declared assurance levels do
   * not match what is sent as authn context.
   * </p>
   */
  @Override
  protected AuthnRequestGeneratorContext createAuthnRequestContext(final AuthnRequirements authnRequirements,
      final SignMessage signMessage, final SignServiceContext context, final EntityDescriptor idpMetadata)
      throws UserAuthenticationException {

    // Since we don't include a RequestAuthnContext in the AuthnContext, we save the accepted
    // authn context levels in the SignService context (for later controls).
    //
    if (authnRequirements.getAuthnContextIdentifiers() != null
        && !authnRequirements.getAuthnContextIdentifiers().isEmpty()) {
      context.put(REQUESTED_AUTHN_CONTEXT_KEY, String.join(",",
          authnRequirements.getAuthnContextIdentifiers().stream()
              .map(AuthnContextIdentifier::getIdentifier)
              .collect(Collectors.toList())));
    }

    return new AuthnRequestGeneratorContext() {

      @Override
      @Nonnull
      public String getPreferredBinding() {
        return SwamidSamlAuthenticationHandler.this.getPreferredBindingUri();
      }

      /**
       * Never include a RequestedAuthnContext ...
       */
      @Override
      @Nullable
      public RequestedAuthnContextBuilderFunction getRequestedAuthnContextBuilderFunction() {
        return (list, hok) -> null;
      }
    };
  }

  /**
   * Overrides the default implementation with custom checking of requested AuthnContext.
   */
  @Override
  protected void assertAuthnContext(final AuthnRequest authnRequest, final String authnContextClassUri,
      final SignServiceContext context) throws UserAuthenticationException {

    // Fetch the saved AuthnContext(s) read from the sign request.
    //
    final List<String> requestedContexts = Optional.ofNullable(context.get(REQUESTED_AUTHN_CONTEXT_KEY, String.class))
        .map(s -> Arrays.asList(s.split(",", -1)))
        .orElseGet(() -> Collections.emptyList());
    if (requestedContexts.isEmpty()) {
      return;
    }
    if (authnContextClassUri == null) {
      final String msg = "No authn context class received in assertion";
      log.info("{}: {}", context.getId(), msg);
      throw new UserAuthenticationException(AuthenticationErrorCode.UNSUPPORTED_AUTHNCONTEXT, msg);
    }
    if (!requestedContexts.contains(authnContextClassUri)) {
      final String msg = String.format("The received authn context class '%s' was not among the requested %s",
          authnContextClassUri, requestedContexts);
      log.info("{}: {}", context.getId(), msg);
      throw new UserAuthenticationException(AuthenticationErrorCode.UNSUPPORTED_AUTHNCONTEXT, msg);
    }
  }

  /** {@inheritDoc} */
  @Override
  protected void resetContext(final SignServiceContext context) {
    super.resetContext(context);
    context.remove(REQUESTED_AUTHN_CONTEXT_KEY);
  }

  /**
   * We want to make sure that we don't fail on non-signed responses ...
   */
  @Override
  protected ValidationContext createValidationContext(
      final HttpUserRequest httpRequest, final SignServiceContext context) {
    return new ValidationContext(Map.of(SAML2AssertionValidationParameters.SIGNATURE_REQUIRED, Boolean.FALSE));
  }

}
