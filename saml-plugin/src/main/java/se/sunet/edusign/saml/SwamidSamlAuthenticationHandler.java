package se.sunet.edusign.saml;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.saml2.core.build.RequestedAuthnContextBuilder;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingResult;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.signservice.authn.AuthenticationErrorCode;
import se.swedenconnect.signservice.authn.AuthnContextIdentifier;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.authn.UserAuthenticationException;
import se.swedenconnect.signservice.authn.impl.DefaultIdentityAssertion;
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

  /** Key for storing the custom eduSign authentication context URI. */
  public final static String CUSTOM_AUTHN_CONTEXT_URI_CONTEXT_KEY = "eduSign.CUSTOM_AUTHN_CONTEXT";

  /** Key for where we temporarily store which eduPersonAssurance levels that matched requested values. */
  public final static String MATCHED_EDU_PERSON_ASSURANCE_LEVELS_CONTEXT_KEY =
      AbstractSamlAuthenticationHandler.PREFIX + ".MatchedEduPersonAssuranceLevels";

  /** The name for the eduPersonAssurance attribute. */
  private static final String EDU_PERSON_ASSURANCE_NAME = "urn:oid:1.3.6.1.4.1.5923.1.1.1.11";

  /** Authentication context URI for Refeds MFA. */
  private static final String REFEDS_MFA_AUTHN_CONTEXT_URI = "https://refeds.org/profile/mfa";

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
   * Creates an {@link AuthnRequestGeneratorContext} object that is to be used by the configured
   * {@link AuthnRequestGenerator}.
   * <p>
   * This is a customization of the default implementation where we make sure to not include a RequestedAuthnContext
   * element in the request unless REFEDS MFA is requested.
   * </p>
   */
  @Override
  protected AuthnRequestGeneratorContext createAuthnRequestContext(final AuthnRequirements authnRequirements,
      final SignMessage signMessage, final SignServiceContext context, final EntityDescriptor idpMetadata)
      throws UserAuthenticationException {

    final boolean refedsMfaRequested;
    if (authnRequirements.getAuthnContextIdentifiers() != null
        && !authnRequirements.getAuthnContextIdentifiers().isEmpty()) {
      context.put(REQUESTED_AUTHN_CONTEXT_KEY, String.join(",",
          authnRequirements.getAuthnContextIdentifiers().stream()
              .map(AuthnContextIdentifier::getIdentifier)
              .collect(Collectors.toList())));

      refedsMfaRequested = authnRequirements.getAuthnContextIdentifiers().stream()
          .filter(a -> Objects.equals(REFEDS_MFA_AUTHN_CONTEXT_URI, a.getIdentifier()))
          .findFirst()
          .isPresent();
    }
    else {
      refedsMfaRequested = false;
    }

    // We also handle the AL3 as a special case. If AL3 is requested as the only level to appear in the
    // eduPersonAssurance attribute, MFA is required, so we request that (even if not explicitly requested).
    //
    final IdentityAttribute<?> eduPersonAssuranceRequirement = authnRequirements.getRequestedSignerAttributes().stream()
        .filter(a -> Objects.equals(EDU_PERSON_ASSURANCE_NAME, a.getIdentifier()))
        .findFirst()
        .orElse(null);

    final boolean al3Requested = eduPersonAssuranceRequirement != null
        && eduPersonAssuranceRequirement.getValues().size() == 1
        && Objects.equals(EduSignAssuranceLevels.SWAMID_AL3, eduPersonAssuranceRequirement.getValue());

    if (!refedsMfaRequested && al3Requested) {
      context.put(REQUESTED_AUTHN_CONTEXT_KEY, REFEDS_MFA_AUTHN_CONTEXT_URI);
      log.info("{} was requested, but not {} - adding {} to AuthnRequest as requested authn context",
          EduSignAssuranceLevels.SWAMID_AL3, REFEDS_MFA_AUTHN_CONTEXT_URI, REFEDS_MFA_AUTHN_CONTEXT_URI);
    }

    return new AuthnRequestGeneratorContext() {

      @Override
      @Nonnull
      public String getPreferredBinding() {
        return SwamidSamlAuthenticationHandler.this.getPreferredBindingUri();
      }

      @Override
      @Nullable
      public RequestedAuthnContextBuilderFunction getRequestedAuthnContextBuilderFunction() {
        return (list, hok) -> {
          if (refedsMfaRequested || al3Requested) {
            return RequestedAuthnContextBuilder.builder()
                .comparison(AuthnContextComparisonTypeEnumeration.EXACT)
                .authnContextClassRefs(REFEDS_MFA_AUTHN_CONTEXT_URI)
                .build();
          }
          else {
            return null;
          }
        };
      }
    };
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

      // If the attribute is multi-valued, sort it so that the highest level is placed first.
      //
      final List<String> requestedAssuranceLevels = eduPersonAssuranceReq.getValues().stream()
          .map(String.class::cast)
          .sorted(EduSignAssuranceLevels.uriComparator)
          .toList();

      final IdentityAttribute<?> eduPersonAssurance = issuedAttributes.stream()
          .filter(a -> EDU_PERSON_ASSURANCE_NAME.equals(a.getIdentifier()))
          .findFirst()
          .orElse(null);
      if (eduPersonAssurance != null) {

        final List<String> matchedRequiredLevels = new ArrayList<>();
        for (final String level : requestedAssuranceLevels) {
          if (eduPersonAssurance.getValues().stream().filter(v -> Objects.equals(v, level)).findAny().isPresent()) {
            matchedRequiredLevels.add(level);
          }
        }
        if (matchedRequiredLevels.isEmpty()) {
          final String msg = String.format("Requirement for attribute '%s' was %s but assertion contains %s",
              EDU_PERSON_ASSURANCE_NAME, requestedAssuranceLevels, eduPersonAssurance.getValues());
          log.info("{}: {}", context.getId(), msg);
          throw new UserAuthenticationException(AuthenticationErrorCode.MISMATCHING_IDENTITY_ATTRIBUTES, msg);
        }
        // Save the matched levels for later check.
        // Specifically, we need to check if AL3 was matched that we really got the MFA authn context class
        // in the assertion. We cover up for misbehaving IdP:s that deliver AL3 but not MFA.
        //
        context.put(MATCHED_EDU_PERSON_ASSURANCE_LEVELS_CONTEXT_KEY, matchedRequiredLevels.toArray(String[]::new));
      }
      // else, let the super implementation fail ...
    }

    super.assertAttributes(authnRequirements, issuedAttributes, context);

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

  /**
   * Applies special processing for eduSign.
   */
  @Override
  protected IdentityAssertion buildIdentityAssertion(@Nonnull final ResponseProcessingResult result,
      @Nonnull final List<IdentityAttribute<?>> attributes, @Nonnull final SignServiceContext context)
      throws UserAuthenticationException {

    final DefaultIdentityAssertion assertion =
        (DefaultIdentityAssertion) super.buildIdentityAssertion(result, attributes, context);

    // Make additional checks that really concerns the attribute release, but due to the structure we need
    // to apply a little workaround.
    //
    // In this section we apply an extra check if AL3 was matched (i.e., if AL3 was requested to be
    // present in the assertion). In order to AL3 to be accepted, we also require that MFA was used.
    // Some IdP:s misbehave and report AL3 even though MFA was not used. We need to check this now
    // when we know the authentication context class ref from the assertion.
    //
    final List<String> matchedLevels =
        Optional.ofNullable(context.get(MATCHED_EDU_PERSON_ASSURANCE_LEVELS_CONTEXT_KEY, String[].class))
            .map(arr -> new ArrayList<String>(List.of(arr)))
            .orElseGet(() -> new ArrayList<>(0));

    context.remove(MATCHED_EDU_PERSON_ASSURANCE_LEVELS_CONTEXT_KEY);

    if (!matchedLevels.isEmpty()) {
      if (Objects.equals(EduSignAssuranceLevels.SWAMID_AL3, matchedLevels.get(0))) {
        if (!Objects.equals(REFEDS_MFA_AUTHN_CONTEXT_URI, result.getAuthnContextClassUri())) {
          log.warn("Invalid assertion - contains {} but AuthnContextClass {} is missing",
              EduSignAssuranceLevels.SWAMID_AL3, REFEDS_MFA_AUTHN_CONTEXT_URI);

          // We are forgiving, but need to downgrade the matched AL-level.
          //
          if (matchedLevels.size() == 1) {
            final String msg =
                String.format("Requirement for attribute '%s' was %s but assertion does not include MFA signalling",
                    EDU_PERSON_ASSURANCE_NAME, EduSignAssuranceLevels.SWAMID_AL3);
            log.info("{}: {}", context.getId(), msg);
            throw new UserAuthenticationException(AuthenticationErrorCode.MISMATCHING_IDENTITY_ATTRIBUTES, msg);
          }
          // Else remove AL3 from the array.
          // Note: The request contained multiple requested eduPersonAssurance levels, and we still have a match
          // so this is ok ...
          //
          matchedLevels.remove(0);
        }
      }

      // We sort the eduPersonAssurance values so that our matching values are placed first
      // in the list. This is essential since the key-and-cert handler assumes single-valued attributes.
      //
      final IdentityAttribute<?> eduPersonAssurance = assertion.getIdentityAttributes().stream()
          .filter(a -> EDU_PERSON_ASSURANCE_NAME.equals(a.getIdentifier()))
          .findFirst()
          .orElse(null);

      if (eduPersonAssurance != null) {

        final List<String> sortedEduPersonAssuranceValues = new ArrayList<>();
        sortedEduPersonAssuranceValues.addAll(matchedLevels);

        eduPersonAssurance.getValues().stream()
            .filter(v -> !matchedLevels.contains(v))
            .map(String.class::cast)
            .forEach(v -> sortedEduPersonAssuranceValues.add(v));

        final IdentityAttribute<?> updatedEduPersonAssurance =
            new StringSamlIdentityAttribute(
                EDU_PERSON_ASSURANCE_NAME, eduPersonAssurance.getFriendlyName(), sortedEduPersonAssuranceValues);

        final List<IdentityAttribute<?>> updatedAttributes = new ArrayList<>(assertion.getIdentityAttributes());
        updatedAttributes.removeIf(a -> EDU_PERSON_ASSURANCE_NAME.equals(a.getIdentifier()));
        updatedAttributes.add(updatedEduPersonAssurance);
        assertion.setIdentityAttributes(updatedAttributes);
      }
    }

    // OK, finally we assigned the custom authentication context class URI that is to be used
    // in the resulting authentication certificate ...
    //
    final boolean refedsMfa = Objects.equals(REFEDS_MFA_AUTHN_CONTEXT_URI, result.getAuthnContextClassUri());
    final List<String> eduPersonAssuranceValues = assertion.getIdentityAttributes().stream()
        .filter(a -> EDU_PERSON_ASSURANCE_NAME.equals(a.getIdentifier()))
        .map(a -> a.getValues().stream().map(String.class::cast).toList())
        .findFirst()
        .orElseGet(() -> Collections.emptyList());

    if (eduPersonAssuranceValues.isEmpty()) {
      log.warn("No eduPersonAssurance attribute available");
    }
    else {

      // Just warn for a special case before we start ...
      if (!refedsMfa && eduPersonAssuranceValues.contains(EduSignAssuranceLevels.SWAMID_AL3)) {
        log.warn("Invalid assertion - No MFA signalled but contains AL3 - AL3 will be ignored");
      }

      final String customAuthnContextUri;
      if (refedsMfa && eduPersonAssuranceValues.contains(EduSignAssuranceLevels.SWAMID_AL3)) {
        customAuthnContextUri = EduSignAssuranceLevels.SWAMID_AL3;
      }
      else if (eduPersonAssuranceValues.contains(EduSignAssuranceLevels.REFEDS_HIGH)) {
        customAuthnContextUri = refedsMfa
            ? EduSignAssuranceLevels.CUSTOM_REFEDS_HIGH_MFA
            : EduSignAssuranceLevels.REFEDS_HIGH;
      }
      else if (eduPersonAssuranceValues.contains(EduSignAssuranceLevels.SWAMID_AL2)) {
        customAuthnContextUri = refedsMfa
            ? EduSignAssuranceLevels.CUSTOM_SWAMID_AL2_MFA
            : EduSignAssuranceLevels.SWAMID_AL2;
      }
      else if (eduPersonAssuranceValues.contains(EduSignAssuranceLevels.REFEDS_MEDIUM)) {
        customAuthnContextUri = refedsMfa
            ? EduSignAssuranceLevels.CUSTOM_REFEDS_MEDIUM_MFA
            : EduSignAssuranceLevels.REFEDS_MEDIUM;
      }
      else if (eduPersonAssuranceValues.contains(EduSignAssuranceLevels.SWAMID_AL1)) {
        customAuthnContextUri = refedsMfa
            ? EduSignAssuranceLevels.CUSTOM_SWAMID_AL1_MFA
            : EduSignAssuranceLevels.SWAMID_AL1;
      }
      else if (eduPersonAssuranceValues.contains(EduSignAssuranceLevels.REFEDS_LOW)) {
        customAuthnContextUri = refedsMfa
            ? EduSignAssuranceLevels.CUSTOM_REFEDS_LOW_MFA
            : EduSignAssuranceLevels.REFEDS_LOW;
      }
      else {
        log.warn("No valid assurance level found in eduPersonAssurance attribute - {}", eduPersonAssuranceValues);
        customAuthnContextUri = null;
      }

      if (customAuthnContextUri != null) {
        context.put(CUSTOM_AUTHN_CONTEXT_URI_CONTEXT_KEY, customAuthnContextUri);
      }

    }

    return assertion;
  }

  /** {@inheritDoc} */
  @Override
  protected void resetContext(final SignServiceContext context) {
    super.resetContext(context);
    context.remove(REQUESTED_AUTHN_CONTEXT_KEY);
    context.remove(MATCHED_EDU_PERSON_ASSURANCE_LEVELS_CONTEXT_KEY);
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
