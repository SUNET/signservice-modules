package se.sunet.edusign.harica.authn.service;

import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.sunet.edusign.harica.authn.service.dto.CaCertificateRequest;
import se.sunet.edusign.harica.authn.service.dto.CreateUserDetails;
import se.sunet.edusign.harica.authn.service.token.CaCertificateResponse;

/**
 * Session data
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class SessionData {

  private boolean bypassRegUi;
  private boolean registered;
  private CreateUserDetails userDetails;
  private CaCertificateRequest request;
  private String csr;
  private String signatureId;
  private CaCertificateResponse caCertificateResponse;
  private Map certResponseData;

}
