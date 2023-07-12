package se.sunet.edusign.harica.authn.service;

import org.apache.http.StatusLine;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Description
 *
 */
@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class CertificateRequestResult {

  StatusLine statusLine;
  String message;

}
