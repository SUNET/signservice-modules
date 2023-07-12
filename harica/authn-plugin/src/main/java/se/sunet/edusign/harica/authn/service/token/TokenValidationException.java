package se.sunet.edusign.harica.authn.service.token;

import java.io.Serial;

import com.nimbusds.jwt.SignedJWT;

import lombok.Getter;

/**
 * Exception when validating an ID token
 */
public class TokenValidationException extends Exception {

  @Getter private final SignedJWT signedJWT;

  private static final long serialVersionUID = -6908586099690472926L;

  /** {@inheritDoc} */
  public TokenValidationException(String message, SignedJWT signedJWT) {
    super(message);
    this.signedJWT = signedJWT;
  }

  /** {@inheritDoc} */
  public TokenValidationException(String message, Throwable cause, SignedJWT signedJWT) {
    super(message, cause);
    this.signedJWT = signedJWT;
  }

}
