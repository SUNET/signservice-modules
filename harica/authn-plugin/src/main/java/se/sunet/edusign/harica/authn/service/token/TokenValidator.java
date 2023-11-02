package se.sunet.edusign.harica.authn.service.token;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

public class TokenValidator {

  private final TokenCredential trustedCredential;

  public TokenValidator(TokenCredential trustedCredential) {
    this.trustedCredential = trustedCredential;
  }

  public SignedJWT validateToken(String jws) throws TokenValidationException {
    SignedJWT signedJWT = null;
    try {
      signedJWT = SignedJWT.parse(jws);
      JWSVerifier verifier = getVerifier(signedJWT);
      boolean valid = signedJWT.verify(verifier);
      if (!valid) {
        throw new TokenValidationException("ID token signature validation failed", signedJWT);
      }
    }
    catch (ParseException e) {
      throw new TokenValidationException("Unable to parse ID token", e, signedJWT);
    }
    catch (JOSEException e) {
      throw new TokenValidationException("Signature validation error", e, signedJWT);
    }
    catch (CertificateEncodingException | NoSuchAlgorithmException e) {
      throw new TokenValidationException("Invalid trust configuration", e, signedJWT);
    }
    catch (RuntimeException e) {
      throw new TokenValidationException("Invalid token data", e, signedJWT);
    }
    return signedJWT;
  }

  private JWSVerifier getVerifier(SignedJWT signedJWT)
      throws TokenValidationException, CertificateEncodingException, NoSuchAlgorithmException, JOSEException {

    @SuppressWarnings("unused")
    JWSHeader header = signedJWT.getHeader();

    if (trustedCredential == null || trustedCredential == null) {
      throw new TokenValidationException("No trusted key available", signedJWT);
    }

    PublicKey publicKey = trustedCredential.getPublicKey();
    if (publicKey == null) {
      throw new TokenValidationException(
          "No trusted public key matches the Id token JWT header declarations", signedJWT);
    }

    if (publicKey instanceof ECPublicKey) {
      return new ECDSAVerifier((ECPublicKey) publicKey);
    }
    return new RSASSAVerifier((RSAPublicKey) publicKey);
  }

}
