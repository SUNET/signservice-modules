package se.sunet.edusign.harica.authn.service;

import org.apache.http.StatusLine;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * User registration result data class
 */
@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class UserRegistrationResult {

  boolean preExistingUser;
  boolean newRegistration;
  StatusLine statusLine;
  String message;

}
