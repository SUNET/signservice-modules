package se.sunet.edusign.harica.authn.service;

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
  int responseCode;
  String message;

}
