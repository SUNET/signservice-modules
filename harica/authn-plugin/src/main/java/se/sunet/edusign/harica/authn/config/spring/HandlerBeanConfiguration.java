package se.sunet.edusign.harica.authn.config.spring;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import com.nimbusds.jose.JWSAlgorithm;

import se.sunet.edusign.harica.authn.HaricaCAAuthenticationHandler;
import se.sunet.edusign.harica.authn.config.CaConfiguration;
import se.sunet.edusign.harica.authn.config.HaricaCAAuthenticationFactory;
import se.sunet.edusign.harica.authn.config.HaricaCAAuthenticationHandlerConfiguration;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Spring @Configuration class for providing the {@link HaricaCAAuthenticationHandler} as a bean
 */
@Configuration
public class HandlerBeanConfiguration {

  /**
   * Creates the Harica AuthenticationHandler as a Bean
   *
   * @param properties configuration properties for the authentication handler
   * @return {@link HaricaCAAuthenticationHandler} bean
   * @throws CertificateException error parsing certificate data
   * @throws NoSuchProviderException no Bouncycastle provider is available
   * @throws IOException error processing property data
   */
  @Bean
  HaricaCAAuthenticationHandler haricaCAAuthenticationHandler(HaricaAuthHandlerConfigurationProperties properties)
    throws CertificateException, NoSuchProviderException, IOException {

    HaricaCAAuthenticationHandlerConfiguration configuration = getConfiguration(properties);
    HaricaCAAuthenticationFactory factory = new HaricaCAAuthenticationFactory();

    return (HaricaCAAuthenticationHandler) factory.create(configuration);
  }

  private HaricaCAAuthenticationHandlerConfiguration getConfiguration(HaricaAuthHandlerConfigurationProperties properties)
    throws CertificateException, NoSuchProviderException, IOException {

    HaricaCAAuthenticationHandlerConfiguration configuration = new HaricaCAAuthenticationHandlerConfiguration();
    configuration.setSpUrlConfiguration(configuration.getSpUrlConfiguration());
    configuration.setCaConfiguration(getCaConfiguration(properties.getCa()));
    configuration.setHttpProxyConfiguration(properties.getHttpProxy());
    configuration.setConnectTimeout(properties.getConnectTimeout());
    configuration.setReadTimeout(properties.getReadTimeout());
    configuration.setRequestSigningCredential(getCredential(properties.getRequestSigningCredential()));
    configuration.setRequestSigningAlgorithm(new JWSAlgorithm(properties.getRequestSigningAlgorithm()));
    configuration.setTrustedCaTokenSignerCert(getCertificate(properties.getTrustedCaTokenSignerCert()));
    configuration.setEmailAdressSource(properties.getEmailAdressSource());
    configuration.setUniqueIdentifierSource(properties.getUniqueIdentifierSource());
    configuration.setSurnameSource(properties.getSurnameSource());
    configuration.setGivenNameSource(properties.getGivenNameSource());
    return configuration;
  }

  private X509Certificate getCertificate(Resource trustedCaTokenSignerCert)
    throws CertificateException, NoSuchProviderException, IOException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
    try(InputStream is = new FileInputStream(trustedCaTokenSignerCert.getFile())){
      return (X509Certificate) cf.generateCertificate(is);
    }
  }

  private PkiCredential getCredential(HaricaAuthHandlerConfigurationProperties.CredentialConfiguration keyProp) {
    return new KeyStoreCredential(keyProp.getLocation(), keyProp.getType(), keyProp.getPassword().toCharArray(),
      keyProp.getAlias(), keyProp.getPassword().toCharArray());
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
}