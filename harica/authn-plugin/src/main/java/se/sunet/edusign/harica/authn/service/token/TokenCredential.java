package se.sunet.edusign.harica.authn.service.token;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import lombok.Getter;

/**
 * Token verification credential data
 */
@Getter
public class TokenCredential {

  private X509Certificate certificate;
  private PublicKey publicKey;
  private byte[] sha256Hash;
  private String kid;

  public TokenCredential(X509Certificate certificate, PublicKey publicKey, byte[] sha256Hash, String kid) {
    this.certificate = certificate;
    this.publicKey = publicKey;
    this.sha256Hash = sha256Hash;
    this.kid = kid;
  }

  /**
   * Create ID token verification credential based on a certificate with no kid
   *
   * @param certificate trusted certificate
   */
  public TokenCredential(X509Certificate certificate) {
    this(certificate, certificate.getPublicKey(), getThumbprint(certificate), null);
  }

  /**
   * Create ID token verification credential based on a certificate with kid
   *
   * @param certificate trusted certificate
   * @param kid key identifier
   */
  public TokenCredential(X509Certificate certificate, String kid) {
    this(certificate, certificate.getPublicKey(), getThumbprint(certificate), kid);
  }

  public TokenCredential(PublicKey publicKey, String kid) {
    this (null, publicKey, null, kid);
  }

  public TokenCredential(PublicKey publicKey) {
    this (null, publicKey, null, null);
  }

  private static byte[] getThumbprint(X509Certificate certificate) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      return md.digest(certificate.getEncoded());
    }
    catch (CertificateEncodingException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
