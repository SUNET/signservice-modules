package se.sunet.edusign.harica.authn.service;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.hc.core5.http.message.StatusLine;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class CertificateRequestResult {

  StatusLine statusLine;
  String message;

}
