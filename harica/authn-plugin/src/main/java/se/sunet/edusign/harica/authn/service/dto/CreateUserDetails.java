package se.sunet.edusign.harica.authn.service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Description
 */

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CreateUserDetails {

  private String email;
  private String givenName;
  private String surname;
  private String uniqueIdentifier;

}
