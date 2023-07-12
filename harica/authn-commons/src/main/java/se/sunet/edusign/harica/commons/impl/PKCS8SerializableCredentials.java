package se.sunet.edusign.harica.commons.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemWriter;

import lombok.extern.slf4j.Slf4j;
import se.sunet.edusign.harica.commons.SerializableCredentials;

/**
 * Implementation of the {@link SerializableCredentials} that stores the private key as PEM formatted PKCS8 data
 */
@Slf4j
public class PKCS8SerializableCredentials implements SerializableCredentials {
  private static final long serialVersionUID = 2498510487438648389L;

  private static final CertificateFactory cf;

  static {
    try {
      cf = CertificateFactory.getInstance("X.509", "BC");
    }
    catch (CertificateException | NoSuchProviderException e) {
      throw new RuntimeException(e);
    }
  }

  /** Private key in PKCS8 format */
  private String privateKey;

  /** Certificate chain as list of raw byte representations of DER encoded certificates */
  private List<byte[]> chain;

  /** Public key in PEM format */
  private String publicKey;

  /**
   * Constructor for key pair with no certificate chain
   *
   * @param privateKey private key
   * @param publicKey public key
   */
  public PKCS8SerializableCredentials(PrivateKey privateKey, PublicKey publicKey) {
    this.privateKey = encodeKeyObject(privateKey);
    this.publicKey = encodeKeyObject(publicKey);
  }

  /**
   * Constructor for private key with certificate chain
   *
   * @param privateKey private key
   * @param certChain certificate chain
   */
  public PKCS8SerializableCredentials(PrivateKey privateKey, List<X509Certificate> certChain) {
    this.privateKey = encodeKeyObject(privateKey);
    Objects.requireNonNull(certChain, "Certificate chain cant be null");
    setCertificateChain(certChain);
  }

  /** {@inheritDoc} */
  @Override public PrivateKey getPrivateKey() {
    if (this.privateKey == null) {
      return null;
    }
    try (PEMParser pemParser = new PEMParser(new StringReader(privateKey))) {
      return new JcaPEMKeyConverter().getPrivateKey(getPrivateKeyInfo(pemParser.readObject()));
    }
    catch (IOException e) {
      throw new RuntimeException("Unable to parse private key", e);
    }
  }

  /** {@inheritDoc} */
  @Override public PublicKey getPublicKey() {
    if (this.publicKey != null) {
      try (PEMParser pemParser = new PEMParser(new StringReader(publicKey))) {
        return new JcaPEMKeyConverter().getPublicKey(getPublicKeyInfo(pemParser.readObject()));
      }
      catch (IOException e) {
        throw new RuntimeException("Unable to parse private key", e);
      }
    }
    return getCertificate() == null ? null : getCertificate().getPublicKey();
  }

  /** {@inheritDoc} */
  @Override public X509Certificate getCertificate() {
    return getCertificateChain().isEmpty() ? null : getCertificateChain().get(0);
  }

  /** {@inheritDoc} */
  @Override public List<X509Certificate> getCertificateChain() {
    if (this.chain == null) {
      this.chain = new ArrayList<>();
    }
    List<X509Certificate> certChain = new ArrayList<>();
    for (byte[] certBytes : chain) {
      try (InputStream is = new ByteArrayInputStream(certBytes)) {
        certChain.add((X509Certificate) cf.generateCertificate(is));
      }
      catch (IOException | CertificateException e) {
        throw new RuntimeException("Error reconstructing certificates", e);
      }
    }

    return certChain;
  }

  /** {@inheritDoc} */
  @Override public void setCertificateChain(List<X509Certificate> certificateChain) {
    this.chain = new ArrayList<>();
    try {
      for (X509Certificate certificate : certificateChain) {
        this.chain.add(certificate.getEncoded());
      }
    }
    catch (CertificateEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  /** {@inheritDoc} */
  @Override public void destroy() {
    this.publicKey = null;
    this.privateKey = null;
    this.chain = null;
  }

  private static String encodeKeyObject(Object keyObject) {
    StringWriter stringWriter = new StringWriter();
    try (PemWriter pemWriter = new PemWriter(stringWriter)) {
      pemWriter.writeObject(new JcaMiscPEMGenerator(keyObject));
      pemWriter.flush();
    }
    catch (IOException e) {
      throw new RuntimeException(e);
    }
    return stringWriter.toString();
  }

  private static PrivateKeyInfo getPrivateKeyInfo(Object pemObject) {
    if (pemObject instanceof PEMKeyPair) {
      PEMKeyPair pemKeyPair = (PEMKeyPair) pemObject;
      return pemKeyPair.getPrivateKeyInfo();
    }
    else if (pemObject instanceof PrivateKeyInfo) {
      return (PrivateKeyInfo) pemObject;
    }
    throw new RuntimeException("Unable to parse private key info");
  }

  private static SubjectPublicKeyInfo getPublicKeyInfo(Object pemObject) {
    if (pemObject instanceof SubjectPublicKeyInfo) {
      return (SubjectPublicKeyInfo) pemObject;
    }
    throw new RuntimeException("Unable to parse publik key info");
  }
}
