package se.sunet.edusign.harica.authn.service.token;

import java.security.cert.X509Certificate;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response data from CA
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CaCertificateResponse {

  private X509Certificate certificate;

  private List<X509Certificate> chain;

  private String uniqueIdentifier;

  private String signatureId;

}
