package se.sunet.edusign.harica.authn.service;

import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;

import lombok.RequiredArgsConstructor;
import se.sunet.edusign.harica.authn.config.CaConfiguration;
import se.sunet.edusign.harica.authn.service.dto.CaCertificateRequest;

/**
 * Service for requesting certificate
 */
@RequiredArgsConstructor
public class CertificateRequestService {

  private final CARequestConnector caRequestConnector;
  private final BackChannelRequestSigner backChannelRequestSigner;
  private final CaConfiguration caConfiguration;

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  public CertificateRequestResult registerCertificateRequest(CaCertificateRequest caCertificateRequest)
    throws IOException, JOSEException {

    byte[] registerUserToken = backChannelRequestSigner.signPayload(OBJECT_MAPPER.writeValueAsBytes(caCertificateRequest));

    HttpResponseData registerCsrResponse = caRequestConnector.postRequest(caConfiguration.getRegisterCsrUrl(), registerUserToken);

    CertificateRequestResult result = CertificateRequestResult.builder()
      .responseCode(registerCsrResponse.getResponseCode())
      .message(caRequestConnector.getStringResponse(registerCsrResponse))
      .build();

    return result;
  }
}
