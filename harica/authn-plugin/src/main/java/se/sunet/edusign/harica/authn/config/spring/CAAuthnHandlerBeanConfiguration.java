package se.sunet.edusign.harica.authn.config.spring;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import com.nimbusds.jose.JWSAlgorithm;

import lombok.extern.slf4j.Slf4j;
import se.sunet.edusign.harica.authn.HaricaCAAuthenticationHandler;
import se.sunet.edusign.harica.authn.config.CaConfiguration;
import se.sunet.edusign.harica.authn.config.HaricaCAAuthenticationFactory;
import se.sunet.edusign.harica.authn.config.HaricaCAAuthenticationHandlerConfiguration;

/**
 * Spring @Configuration class for providing the {@link HaricaCAAuthenticationHandler} as a bean
 */
@Slf4j
@ConditionalOnProperty(name = "harica-authn.enabled", havingValue = "true", matchIfMissing = false)
@Configuration
public class CAAuthnHandlerBeanConfiguration {

  /**
   * Creates the Harica AuthenticationHandler as a Bean
   *
   * @param properties configuration properties for the authentication handler
   * @return {@link HaricaCAAuthenticationHandler} bean
   * @throws CertificateException error parsing certificate data
   * @throws NoSuchProviderException no Bouncycastle provider is available
   * @throws IOException error processing property data
   */
  @Bean(name = "signservice.HaricaCAAuthenticationHandler")
  HaricaCAAuthenticationHandler haricaCAAuthenticationHandler(HaricaAuthHandlerConfigurationProperties properties)
    throws CertificateException, NoSuchProviderException, IOException, NoSuchAlgorithmException,
    InvalidKeySpecException {

    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    HaricaCAAuthenticationHandlerConfiguration configuration = getConfiguration(properties);
    HaricaCAAuthenticationFactory factory = new HaricaCAAuthenticationFactory();

    return (HaricaCAAuthenticationHandler) factory.create(configuration);
  }

  private HaricaCAAuthenticationHandlerConfiguration getConfiguration(HaricaAuthHandlerConfigurationProperties properties)
    throws CertificateException, NoSuchProviderException, IOException, NoSuchAlgorithmException,
    InvalidKeySpecException {

    HaricaCAAuthenticationHandlerConfiguration configuration = new HaricaCAAuthenticationHandlerConfiguration();
    configuration.setSpUrlConfiguration(properties.getSpUrl());
    configuration.setCaConfiguration(getCaConfiguration(properties.getCa()));
    configuration.setHttpProxyConfiguration(properties.getHttpProxy());
    configuration.setConnectTimeout(properties.getConnectTimeout());
    configuration.setReadTimeout(properties.getReadTimeout());
    configuration.setRequestSigningCredential(getCredential(properties.getRequestSigningCredential()));
    configuration.setRequestSigningAlgorithm(new JWSAlgorithm(properties.getRequestSigningAlgorithm()));
    configuration.setTrustedCaTokenVerificationKey(getPublicKey(properties.getTrustedCaTokenVerificationKey()));
    configuration.setEmailAdressSource(properties.getEmailAdressSource());
    configuration.setUniqueIdentifierSource(properties.getUniqueIdentifierSource());
    configuration.setSurnameSource(properties.getSurnameSource());
    configuration.setGivenNameSource(properties.getGivenNameSource());
    return configuration;
  }

  private PublicKey getPublicKey(Resource publicKeyResource) throws IOException {
    File pemFile = publicKeyResource.getFile();
    try (PEMParser pemParser = new PEMParser(new FileReader(pemFile))) {
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
      SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
      return converter.getPublicKey(publicKeyInfo);
    }
  }

  private PrivateKey getCredential(HaricaAuthHandlerConfigurationProperties.CredentialConfiguration keyProp)
    throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {

    byte[] inBytes = Base64.decode(IOUtils.toByteArray(keyProp.getEcPrivateKey().getInputStream()));

    try {
      return parsePkcs8PrivateKey(inBytes);
    }
    catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
      log.debug("Attempts to decode raw private key failed. Attempting to build PKCS8 wrapper");
    }

    // Construct PKCS#8 Key
    ASN1EncodableVector pkcs8Vector = new ASN1EncodableVector();
    pkcs8Vector.add(new ASN1Integer(BigInteger.ZERO));
    ASN1EncodableVector algoIdVector = new ASN1EncodableVector();
    algoIdVector.add(new ASN1ObjectIdentifier("1.2.840.10045.2.1"));
    algoIdVector.add(new ASN1ObjectIdentifier("1.2.840.10045.3.1.7"));
    pkcs8Vector.add(new DERSequence(algoIdVector));
    pkcs8Vector.add(new DEROctetString(inBytes));
    byte[] pkcs8PrivKey = new DERSequence(pkcs8Vector).getEncoded("DER");
    return parsePkcs8PrivateKey(pkcs8PrivKey);
  }

  private PrivateKey parsePkcs8PrivateKey(byte[] pkcs8PrivKey)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
    EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8PrivKey);
    PrivateKey privateKey = kf.generatePrivate(keySpec);
    return privateKey;
  }


  private CaConfiguration getCaConfiguration(HaricaAuthHandlerConfigurationProperties.CaConfigProperties ca)
    throws CertificateException, IOException, NoSuchProviderException {

    CaConfiguration caConfiguration = new CaConfiguration();

    caConfiguration.setGetUserUrl(ca.getGetUserUrl());
    caConfiguration.setRegisterUserUrl(ca.getRegisterUserUrl());
    caConfiguration.setRegisterCsrUrl(ca.getRegisterCsrUrl());
    caConfiguration.setCertificateIssuanceUrl(ca.getCertificateIssuanceUrl());
    caConfiguration.setAllowNewUserRegistration(ca.isAllowNewUserRegistration());
    caConfiguration.setKeyGenType(ca.getKeyGenType());
    caConfiguration.setCertReqAlgo(ca.getCertReqAlgo());
    caConfiguration.setCaCertificateChain(getCertificateChain(ca.getCaCertificateChain()));
    caConfiguration.setLoa(ca.getLoa());
    return caConfiguration;
  }

  private List<X509Certificate> getCertificateChain(List<Resource> caCertificateChain)
    throws CertificateException, IOException, NoSuchProviderException {

    List<X509Certificate> chain = new ArrayList<>();
    for (Resource cerResource : caCertificateChain) {
      chain.add(getCertificate(cerResource));
    }
    return chain;
  }

  private X509Certificate getCertificate(Resource trustedCaTokenSignerCert)
    throws CertificateException, NoSuchProviderException, IOException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
    try(InputStream is = new FileInputStream(trustedCaTokenSignerCert.getFile())) {
      return (X509Certificate) cf.generateCertificate(is);
    }
  }
}