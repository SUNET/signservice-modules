package se.sunet.edusign.harica.commons.impl;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.lang3.reflect.FieldUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.InMemoryPkiCredentialContainer;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;
import se.sunet.edusign.harica.commons.SerializableCredentials;

/**
 * Test for
 */
@Slf4j
class PKCS8SerializableCredentialsTest {

  static PkiCredentialContainer credentialContainer;
  static PkiCredential ecCredential;
  static PkiCredential rsaCredential;

  static PkiCredential ecJksCredential;
  static PkiCredential rsaJksCredential;

  @BeforeAll
  static void init() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    credentialContainer = new InMemoryPkiCredentialContainer("BC");
    ecCredential = credentialContainer.getCredential(credentialContainer.generateCredential(KeyGenType.EC_P256));
    rsaCredential = credentialContainer.getCredential(credentialContainer.generateCredential(KeyGenType.RSA_3072));

    Resource jksResource = new FileSystemResource(PKCS8SerializableCredentialsTest.class.getClassLoader().getResource("testKeys.jks").getFile());
    ecJksCredential = new KeyStoreCredential(jksResource, "Test1234".toCharArray(), "ec", "Test1234".toCharArray());
    rsaJksCredential = new KeyStoreCredential(jksResource, "Test1234".toCharArray(), "rsa", "Test1234".toCharArray());
  }

  @BeforeEach
  void setUp() {
  }

  @Test
  void getPrivateAndPublicKey() throws Exception {
    log.info("Testing EC key serialization");
    getAndTestKeys(ecCredential.getPrivateKey(), ecCredential.getPublicKey());
    log.info("Testing RSA key serialization");
    getAndTestKeys(rsaCredential.getPrivateKey(), rsaCredential.getPublicKey());
  }

  void getAndTestKeys(PrivateKey privateKey, PublicKey publicKey) throws Exception {

    SerializableCredentials sc = new PKCS8SerializableCredentials(privateKey, publicKey);
    PrivateKey recoveredPrivate = sc.getPrivateKey();
    assertEquals(privateKey, recoveredPrivate);

    PublicKey recoveredPublic = sc.getPublicKey();
    assertEquals(publicKey, recoveredPublic);

    log.info("Successfully parsed recovered keys");

    String pkcs8Private = (String) FieldUtils.readField(sc, "privateKey", true);
    log.info("Private key:\n{}", pkcs8Private);

    String pkcs8Public = (String) FieldUtils.readField(sc, "publicKey", true);
    log.info("Public key:\n{}", pkcs8Public);

  }

  @Test
  void getCertificates() {

    log.info("Get EC certificates from credential added after construction");
    testGetCertificates(ecJksCredential, true);
    log.info("Get EC certificates from credential set at construction");
    testGetCertificates(ecJksCredential, false);
    log.info("Get RSA certificates from credential added after construction");
    testGetCertificates(rsaJksCredential, true);
    log.info("Get RSA certificates from credential set at construction");
    testGetCertificates(rsaJksCredential, false);
  }

  void testGetCertificates(PkiCredential credential, boolean postAdd) {

    List<X509Certificate> chain = credential.getCertificateChain();
    X509Certificate certificate = credential.getCertificate();

    SerializableCredentials sc;
    if (!postAdd) {
      sc = new PKCS8SerializableCredentials(credential.getPrivateKey(), credential.getCertificateChain());
    }
    sc = new PKCS8SerializableCredentials(credential.getPrivateKey(), credential.getPublicKey());
    sc.setCertificateChain(credential.getCertificateChain());

    List<X509Certificate> recoveredChain = sc.getCertificateChain();
    assertNotNull(recoveredChain);
    log.info("Recovered chain is not null");
    assertEquals(chain.size(), recoveredChain.size());
    log.info("Recovered chain has expected size {}", chain.size());
    for (int i = 0; i < chain.size(); i++) {
      assertEquals(chain.get(i), recoveredChain.get(i));
      log.info("Chain certificate {} match:\n{}", i, chain.get(i));
    }

    assertEquals(certificate, sc.getCertificate());
    log.info("Primary certificate match\n{}", certificate);

  }

  @Test
  void destroy() throws Exception {

    log.info("Testing destroy function");

    SerializableCredentials sc = new PKCS8SerializableCredentials(ecJksCredential.getPrivateKey(), ecJksCredential.getPublicKey());
    sc.setCertificateChain(ecJksCredential.getCertificateChain());

    assertNotNull(sc.getPrivateKey());
    assertNotNull(sc.getPublicKey());
    assertEquals(1, sc.getCertificateChain().size());
    assertNotNull(sc.getCertificate());

    sc.destroy();

    assertNull(sc.getPrivateKey());
    assertNull(sc.getPublicKey());
    assertTrue(sc.getCertificateChain().isEmpty());
    assertNull(sc.getCertificate());
    log.info("PKCS8SerializableCredentials successfully destroyed");

  }

  @Test
  void testSerialization() {
    SerializableCredentials sc = new PKCS8SerializableCredentials(ecJksCredential.getPrivateKey(), ecJksCredential.getPublicKey());
    sc.setCertificateChain(ecJksCredential.getCertificateChain());

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      oos.writeObject(sc);
      oos.flush();
    }
    catch (IOException e) {
      throw new RuntimeException(e);
    }
    byte[] serializedCredentials = bos.toByteArray();
    log.info("Serialized credentials: \n{}", Hex.toHexString(serializedCredentials));

    SerializableCredentials recSc;
    ByteArrayInputStream bis = new ByteArrayInputStream(serializedCredentials);
    try(ObjectInputStream ois = new ObjectInputStream(bis)) {
      recSc = (PKCS8SerializableCredentials) ois.readObject();
    }
    catch (IOException | ClassNotFoundException e) {
      throw new RuntimeException(e);
    }

    assertEquals(sc.getPrivateKey(), recSc.getPrivateKey());
    assertEquals(sc.getPublicKey(), recSc.getPublicKey());
    assertEquals(sc.getCertificate(), recSc.getCertificate());

    log.info("Recovered serialized credentials match");
  }
}