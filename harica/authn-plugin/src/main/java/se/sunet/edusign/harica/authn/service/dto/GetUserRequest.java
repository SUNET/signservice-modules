package se.sunet.edusign.harica.authn.service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Get user request data
 */
@AllArgsConstructor
@Data
public class GetUserRequest {
  String uniqueIdentifier;

}
