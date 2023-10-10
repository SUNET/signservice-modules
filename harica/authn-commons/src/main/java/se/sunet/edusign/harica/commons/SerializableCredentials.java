package se.sunet.edusign.harica.commons;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface for storing serializable credential data that can recreate the credential and its ability to destroy the
 * key when reconstructed from serialized form.
 */
public interface SerializableCredentials extends Serializable {

  /**
   * Get the private key if present
   *
   * @return private key or null
   */
  PrivateKey getPrivateKey();

  /**
   * Get the public key if present
   *
   * @return public key or null
   */
  PublicKey getPublicKey();

  /**
   * Get the certificate associated with the private key if present
   *
   * @return certificate or null
   */
  X509Certificate getCertificate();

  /**
   * Get the certificate chain if present
   *
   * @return list of certificates. En empty list is returned if no certificates are present
   */
  List<X509Certificate> getCertificateChain();

  /**
   * Set certificate chain post construction
   *
   * @param certificateChain certificate chain
   */
  void setCertificateChain(List<X509Certificate> certificateChain);

  /**
   * Destroy all key material
   */
  void destroy();

}
