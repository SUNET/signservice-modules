package se.sunet.edusign.harica.authn;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.http.StatusLine;
import org.apache.http.client.utils.URIBuilder;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.sunet.edusign.harica.authn.config.CaConfiguration;
import se.sunet.edusign.harica.authn.config.SpUrlConfiguration;
import se.sunet.edusign.harica.authn.result.CAAuthResult;
import se.sunet.edusign.harica.authn.service.CertificateRequestFactory;
import se.sunet.edusign.harica.authn.service.CertificateRequestResult;
import se.sunet.edusign.harica.authn.service.CertificateRequestService;
import se.sunet.edusign.harica.authn.service.UserRegistrationResult;
import se.sunet.edusign.harica.authn.service.UserRegistrationService;
import se.sunet.edusign.harica.authn.service.dto.CaCertificateRequest;
import se.sunet.edusign.harica.authn.service.dto.CreateUserDetails;
import se.sunet.edusign.harica.authn.service.token.CaCertificateResponse;
import se.sunet.edusign.harica.authn.service.token.ResponseParser;
import se.sunet.edusign.harica.authn.service.token.TokenValidationException;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.security.credential.container.PkiCredentialContainerException;
import se.swedenconnect.signservice.authn.AuthenticationErrorCode;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.authn.AuthenticationResultChoice;
import se.swedenconnect.signservice.authn.UserAuthenticationException;
import se.sunet.edusign.harica.authn.service.token.TokenValidator;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.AbstractSignServiceHandler;
import se.swedenconnect.signservice.core.http.DefaultHttpRedirectAction;
import se.swedenconnect.signservice.core.http.DefaultHttpResponseAction;
import se.swedenconnect.signservice.core.http.HttpResponseAction;
import se.swedenconnect.signservice.core.http.HttpUserRequest;
import se.sunet.edusign.harica.commons.SerializableCredentials;
import se.sunet.edusign.harica.commons.impl.PKCS8SerializableCredentials;
import se.swedenconnect.signservice.protocol.msg.AuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.SignMessage;

/**
 * Handler for performing user authentication and certificate issuance using the Harica CA API
 */
@Slf4j
public class HaricaCAAuthenticationHandler extends AbstractSignServiceHandler
  implements AuthenticationHandler {

  /** Prefix for all context values that we store/retrieve. */
  public static final String PREFIX = "se.swedenconnect.signservice.harica";

  /** Key for storing the signer credentials data */
  public static final String SIGNER_CREDENTIAL_KEY = PREFIX + ".SignerCredentials";
  public static final String REQUESTED_AUTH_SERVICE_ID = PREFIX + ".AuthServiceId";

  @Setter
  private String emailAdressSource = "urn:oid:0.9.2342.19200300.100.1.3";
  @Setter
  private String uniqueIdentifierSource = "urn:oid:1.2.752.201.3.7";
  @Setter
  private String surnameSource = "urn:oid:2.5.4.4";
  @Setter
  private String givenNameSource = "urn:oid:2.5.4.42";

  protected final SpUrlConfiguration urlConfiguration;
  protected final CaConfiguration caConfiguration;
  protected final UserRegistrationService userRegistrationService;
  protected final TokenValidator tokenValidator;
  protected final ResponseParser responseParser;
  protected final CertificateRequestService certificateRequestService;
  protected final PkiCredentialContainer credentialContainer;
  protected final CertificateRequestFactory certificateRequestFactory;
  protected final AlgorithmRegistry algorithmRegistry;

  public HaricaCAAuthenticationHandler(
    SpUrlConfiguration urlConfiguration, CaConfiguration caConfiguration,
    UserRegistrationService userRegistrationService,
    TokenValidator tokenValidator,
    ResponseParser responseParser,
    CertificateRequestService certificateRequestService,
    PkiCredentialContainer credentialContainer,
    CertificateRequestFactory certificateRequestFactory,
    AlgorithmRegistry algorithmRegistry) {
    this.urlConfiguration = Objects.requireNonNull(urlConfiguration, "SP URL configuration must not be null");
    this.userRegistrationService = Objects.requireNonNull(userRegistrationService,
      "User registration service must not be null");
    this.caConfiguration = Objects.requireNonNull(caConfiguration,
      "CA configuration must not be null");
    this.tokenValidator = Objects.requireNonNull(tokenValidator,
      "Token validator must not be null");
    this.responseParser = Objects.requireNonNull(responseParser,
      "Response parser must not be null");
    this.certificateRequestService = Objects.requireNonNull(certificateRequestService,
      "Certificate request service must not be null");
    this.credentialContainer = Objects.requireNonNull(credentialContainer,
      "Credential container must not be null");
    this.certificateRequestFactory = Objects.requireNonNull(certificateRequestFactory,
      "Certificate request factory must not be null");
    this.algorithmRegistry = Objects.requireNonNull(algorithmRegistry,
      "Algorithm registry must not be null");
  }

  @Nonnull @Override public AuthenticationResultChoice authenticate(@Nonnull AuthnRequirements authnRequirements,
    @Nullable SignMessage signMessage, @Nonnull SignServiceContext context)
    throws UserAuthenticationException {

    try {
      // Get user details from request input
      CreateUserDetails userDetails = getUserDetails(authnRequirements);
      // Check if user registration is allowed
      boolean allowRegistration = caConfiguration.isAllowNewUserRegistration();
      if (userDetails.getEmail() == null
        || userDetails.getSurname() == null
        || userDetails.getGivenName() == null) {
        // Insufficient input data for registration. Turn registration off
        allowRegistration = false;
      }
      // Check if user is registered or otherwise attempt new registration.
      UserRegistrationResult userRegistrationResult = userRegistrationService.registerUser(userDetails);
      boolean registrationSuccess =
        (allowRegistration && userRegistrationResult.isNewRegistration())
          || userRegistrationResult.isPreExistingUser();
      if (!registrationSuccess) {
        throw new UserAuthenticationException(AuthenticationErrorCode.FAILED_AUTHN,
          "Failed to register the user at the CA");
      }

      // Continue to generate keys and a certificate request
      String credentialId = credentialContainer.generateCredential(caConfiguration.getKeyGenType());
      PkiCredential credential = credentialContainer.getCredential(credentialId);
      final SignatureAlgorithm algorithm = (SignatureAlgorithm) algorithmRegistry.getAlgorithm(
        caConfiguration.getCertReqAlgo());
      String csr = certificateRequestFactory.generatePKCS10Request(userDetails, credential, algorithm);

      // Register certificate request at CA
      CaCertificateRequest caCertificateRequest = new CaCertificateRequest(context.getId(),
        userDetails.getUniqueIdentifier(), csr,
        urlConfiguration.getBaseUrl() + urlConfiguration.getCertificateReturnPath());
      CertificateRequestResult requestResult = certificateRequestService.registerCertificateRequest(
        caCertificateRequest);
      // Get result
      StatusLine status = requestResult.getStatusLine();
      String message = requestResult.getMessage();

      if (status.getStatusCode() != 200) {
        String statusMessage = message == null
          ? "Failed to register certificate request"
          : message;
        throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR, statusMessage);
      }

      // Certificate request registration succeeded. Hand over user to CA service for authentication and certificate issuance
      String certRequestUrl = new URIBuilder(caConfiguration.getCertificateIssuanceUrl())
        .addParameter("signatureId", caCertificateRequest.getSignatureId())
        .build()
        .toURL()
        .toExternalForm();
      final HttpResponseAction responseAction = new DefaultHttpResponseAction(
        new DefaultHttpRedirectAction(certRequestUrl));

      // Store data in session required to complete the authentication and certificate issuing process
      context.put(SIGNER_CREDENTIAL_KEY,
        new PKCS8SerializableCredentials(credential.getPrivateKey(), credential.getPublicKey()));
      context.put(REQUESTED_AUTH_SERVICE_ID, authnRequirements.getAuthnServiceID());

      log.debug("{}: Certificate issuing request submitted - {}", context.getId(), responseAction);
      return new AuthenticationResultChoice(responseAction);
    }
    catch (IOException | JOSEException | PkiCredentialContainerException | CertificateException |
           NoSuchAlgorithmException | KeyException | URISyntaxException e) {
      throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR,
        "Error processing authentication request", e);
    }
  }

  private CreateUserDetails getUserDetails(AuthnRequirements authnRequirements) throws UserAuthenticationException {

    String uniqueId = Optional.ofNullable(getReqAttrVal(authnRequirements, uniqueIdentifierSource))
      .orElseThrow(() -> new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR,
        "User unique identifier from source " + uniqueIdentifierSource + " is not specified in request"));

    return CreateUserDetails.builder()
      .uniqueIdentifier(uniqueId)
      .email(getReqAttrVal(authnRequirements, emailAdressSource))
      .givenName(getReqAttrVal(authnRequirements, givenNameSource))
      .surname(getReqAttrVal(authnRequirements, surnameSource))
      .build();
  }

  private String getReqAttrVal(AuthnRequirements authnRequirements, String attributeId) {
    return authnRequirements.getRequestedSignerAttributes().stream()
      .filter(identityAttribute -> identityAttribute.getIdentifier() != null)
      .filter(identityAttribute -> identityAttribute.getIdentifier().equals(attributeId))
      .filter(identityAttribute -> !identityAttribute.isMultiValued())
      .filter(identityAttribute -> identityAttribute.getAttributeValueType().equals(String.class))
      .map(identityAttribute -> (String) identityAttribute.getValue())
      .findFirst()
      .orElse(null);
  }

  @Nonnull @Override public AuthenticationResultChoice resumeAuthentication(@Nonnull HttpUserRequest httpRequest,
    @Nonnull SignServiceContext context) throws UserAuthenticationException {

    log.debug(
      "{}: Certificate request authentication handler '{}' received request to resume authentication (process response)",
      context.getId(), this.getName());

    SerializableCredentials serializableCredentials = context.get(SIGNER_CREDENTIAL_KEY);
    String authServiceId = context.get(REQUESTED_AUTH_SERVICE_ID);

    try {
      final String certResponseJwt = httpRequest.getParameter("JWS");
      SignedJWT signedJWT = tokenValidator.validateToken(certResponseJwt);
      CaCertificateResponse caCertificateResponse = responseParser.parseTokenPayload(signedJWT.getPayload());
      if (caCertificateResponse.getCertificate() == null) {
        throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR,
          "No certificate was returned from CA");
      }
      List<X509Certificate> signerChain = new ArrayList<>();
      signerChain.add(caCertificateResponse.getCertificate());
      signerChain.addAll(caConfiguration.getCaCertificateChain());
      assert serializableCredentials != null;
      serializableCredentials.setCertificateChain(signerChain);
      // Store the signing credentials
      context.put(SIGNER_CREDENTIAL_KEY, serializableCredentials);
      // Convert issued certificate to assertion and conclude authentication result
      // NOTE that we never display sign message, and we will always return the requested IdP ID as the response IdP for
      // interop reasons. The IdP declaration is redundant for this handler
      return new AuthenticationResultChoice(
        new CAAuthResult(caCertificateResponse.getCertificate(), caConfiguration.getLoa(), uniqueIdentifierSource,
          authServiceId, false));
    }
    catch (CertificateException | IOException | TokenValidationException e) {
      throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR, "Failed to issue certificate",
        e);
    }
  }

  @Override public boolean canProcess(@Nonnull HttpUserRequest httpRequest,
    @Nullable SignServiceContext context) {
    if (httpRequest.getParameter("JWS") == null) {
      final String msg = "Certificate response parameter in response";
      log.debug("{}: {}", Optional.ofNullable(context).map(SignServiceContext::getId).orElse(""), msg);
      return false;
    }

    final String requestPath = httpRequest.getServerServletPath();
    if (!requestPath.equalsIgnoreCase(this.urlConfiguration.getCertificateReturnPath())) {
      log.info("{}: Path {} is not supported by handler '{}'",
        Optional.ofNullable(context).map(SignServiceContext::getId).orElse(""), requestPath, this.getName());
      return false;
    }

    return true;
  }
}
