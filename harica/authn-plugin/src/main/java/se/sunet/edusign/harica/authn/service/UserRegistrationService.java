package se.sunet.edusign.harica.authn.service;

import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;

import lombok.RequiredArgsConstructor;
import se.sunet.edusign.harica.authn.config.CaConfiguration;
import se.sunet.edusign.harica.authn.service.dto.CreateUserDetails;
import se.sunet.edusign.harica.authn.service.dto.GetUserRequest;

/**
 * This service handles user registration before signing
 */

@RequiredArgsConstructor
public class UserRegistrationService {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private final CARequestConnector caRequestConnector;
  private final BackChannelRequestSigner backChannelRequestSigner;
  private final CaConfiguration caConfiguration;


  public UserRegistrationResult registerUser(CreateUserDetails userDetails) throws IOException, JOSEException {

    GetUserRequest getUserRequest = new GetUserRequest(userDetails.getUniqueIdentifier());
    byte[] userRequestToken = backChannelRequestSigner.signPayload(OBJECT_MAPPER.writeValueAsBytes(getUserRequest));

    HttpResponseData getUserResponse = caRequestConnector.postRequest(caConfiguration.getGetUserUrl(), userRequestToken);
    if (getUserResponse.getResponseCode() == 200) {
      return UserRegistrationResult.builder()
        .preExistingUser(true)
        .newRegistration(false)
        .responseCode(getUserResponse.getResponseCode())
        .message(caRequestConnector.getStringResponse(getUserResponse))
        .build();
    }

    // User is not present at the CA. Attempt registration
    byte[] registerUserToken = backChannelRequestSigner.signPayload(OBJECT_MAPPER.writeValueAsBytes(userDetails));
    HttpResponseData registerUserResponse = caRequestConnector.postRequest(caConfiguration.getRegisterUserUrl(), registerUserToken);

    UserRegistrationResult registrationResult = UserRegistrationResult.builder()
      .preExistingUser(false)
      .newRegistration(registerUserResponse.getResponseCode() == 200)
      .responseCode(registerUserResponse.getResponseCode())
      .message(caRequestConnector.getStringResponse(registerUserResponse))
      .build();

    return registrationResult;
  }


}
