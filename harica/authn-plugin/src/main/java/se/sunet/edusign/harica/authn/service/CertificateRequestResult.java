package se.sunet.edusign.harica.authn.service;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class CertificateRequestResult {

  int responseCode;
  String message;

}
