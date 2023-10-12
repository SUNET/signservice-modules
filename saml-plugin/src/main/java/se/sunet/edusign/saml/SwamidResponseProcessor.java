package se.sunet.edusign.saml;

import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.common.assertion.ValidationResult;
import org.opensaml.saml.saml2.assertion.ConditionValidator;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.assertion.StatementValidator;
import org.opensaml.saml.saml2.assertion.SubjectConfirmationValidator;
import org.opensaml.saml.saml2.assertion.impl.AudienceRestrictionConditionValidator;
import org.opensaml.saml.saml2.assertion.impl.BearerSubjectConfirmationValidator;
import org.opensaml.saml.saml2.assertion.impl.HolderOfKeySubjectConfirmationValidator;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Condition;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Statement;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.xmlsec.signature.support.SignaturePrevalidator;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.saml2.assertion.validation.AssertionValidator;
import se.swedenconnect.opensaml.saml2.assertion.validation.AuthnStatementValidator;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingInput;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessorImpl;
import se.swedenconnect.opensaml.saml2.response.validation.ResponseValidationException;

/**
 * A SAML response processor with fixes for the Swamid federation.
 *
 * @author Martin Lindström
 */
@Slf4j
public class SwamidResponseProcessor extends ResponseProcessorImpl {

  private static final String RESPONSE_SIGNED_PARAMETER = "swamid.ResponseSigned";

  @Override
  protected void validateResponse(final Response response, final String relayState, final ResponseProcessingInput input,
      final EntityDescriptor idpMetadata, final ValidationContext validationContext)
      throws ResponseValidationException {

    validationContext.getDynamicParameters().put(RESPONSE_SIGNED_PARAMETER, Boolean.valueOf(response.isSigned()));
    super.validateResponse(response, relayState, input, idpMetadata, validationContext);
  }

  /**
   * Creates a Swamid assertion validator.
   */
  @Override
  protected AssertionValidator createAssertionValidator(final SignatureTrustEngine signatureTrustEngine,
      final SignaturePrevalidator signatureProfileValidator) {

    return new SwamidAssertionValidator(signatureTrustEngine, signatureProfileValidator,
        Arrays.asList(new BearerSubjectConfirmationValidator(), new HolderOfKeySubjectConfirmationValidator()),
        Arrays.asList(new AudienceRestrictionConditionValidator()),
        Arrays.asList(new AuthnStatementValidator()));
  }

  /**
   * A validator for assertions issued by Swamid IdP:s.
   *
   * @author Martin Lindström
   */
  private static class SwamidAssertionValidator extends AssertionValidator {

    /**
     * Constructor.
     *
     * @param trustEngine the trust used to validate the object's signature
     * @param signaturePrevalidator the signature pre-validator used to pre-validate the object's signature
     * @param confirmationValidators validators used to validate {@link SubjectConfirmation} methods within the
     *          assertion
     * @param conditionValidators validators used to validate the {@link Condition} elements within the assertion
     * @param statementValidators validators used to validate {@link Statement}s within the assertion
     */
    public SwamidAssertionValidator(final SignatureTrustEngine trustEngine,
        final SignaturePrevalidator signaturePrevalidator,
        final Collection<SubjectConfirmationValidator> confirmationValidators,
        final Collection<ConditionValidator> conditionValidators,
        final Collection<StatementValidator> statementValidators) {
      super(trustEngine, signaturePrevalidator, confirmationValidators, conditionValidators, statementValidators);
    }

    /**
     * If the response was signed and the assertion isn't signed, we are ok even if assertion signing is required ...
     */
    @Override
    protected ValidationResult validateSignature(final Assertion token, final ValidationContext context) {

      final boolean responseSigned = Optional.ofNullable(context.getDynamicParameters().get(RESPONSE_SIGNED_PARAMETER))
          .map(Boolean.class::cast)
          .orElse(false);

      final boolean assertionSignatureRequired = Optional.ofNullable(
          context.getStaticParameters().get(SAML2AssertionValidationParameters.SIGNATURE_REQUIRED))
          .map(Boolean.class::cast)
          .orElse(true);

      if (!token.isSigned()) {
        if (responseSigned) {
          if (assertionSignatureRequired) {
            log.warn("Assertion was required to be signed, but was not. Will be allowed anyway since response was signed");
          }
          else {
            log.debug("Assertion was not required to be signed, and was not signed. Skipping further signature evaluation");
          }
          return ValidationResult.VALID;
        }
        else {
          context.setValidationFailureMessage("Assertion was not signed, nor was SAML response - invalid message");
          return ValidationResult.INVALID;
        }
      }
      if (trustEngine == null) {
        log.warn("Signature validation was necessary, but no signature trust engine was available");
        context.setValidationFailureMessage(String.format(
          "%s signature could not be evaluated due to internal error", this.getObjectName()));
        return ValidationResult.INDETERMINATE;
      }

      return this.performSignatureValidation(token, context);
    }

  }

}
