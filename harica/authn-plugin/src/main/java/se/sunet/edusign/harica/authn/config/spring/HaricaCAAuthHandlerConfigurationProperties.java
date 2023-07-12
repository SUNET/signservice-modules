package se.sunet.edusign.harica.authn.config.spring;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import lombok.Data;
import se.sunet.edusign.harica.authn.HaricaCAAuthenticationHandler;
import se.sunet.edusign.harica.authn.config.HttpProxyConfiguration;
import se.sunet.edusign.harica.authn.config.SpUrlConfiguration;

/**
 * Configuration properties for creating a {@link HaricaCAAuthenticationHandler} bean
 */
@Configuration
@Data
@ConfigurationProperties(prefix = "harica-authn")
public class HaricaCAAuthHandlerConfigurationProperties {

  /** SP url configuration */
  SpUrlConfiguration spUrl;

  /** CA configuration parameters used by the handler */
  CaConfigProperties ca;

  /** Optional Http Proxy configuration data */
  HttpProxyConfiguration httpProxy;

  /** HTTP connect timeout in milliseconds */
  int connectTimeout;

  /** HTTP read timeout in milliseconds */
  int readTimeout;

  /** Credentials for signing requests to the CA */
  Resource requestSigningCredentialLocation;

  /** Credential type for signing requests to the CA */
  String requestSigningCredentialType;

  /** Algorithm used to sign request to CA */
  String requestSigningAlgorithm;

  /** Trusted certificate for validating certificate result tokens from CA */
  Resource trustedCaTokenSignerCert;

  /** The name of the attribute specified in sign request as the ID of attributes used to provide the e-mail of the signer */
  String emailAdressSource;

  /** The name of the attribute specified in sign request as the ID of attributes used to provide the unique identifier of the signer */
  String uniqueIdentifierSource;

  /** The name of the attribute specified in sign request as the ID of attributes used to provide the surname of the signer */
  String surnameSource;

  /** The name of the attribute specified in sign request as the ID of attributes used to provide the given name of the signer */
  String givenNameSource;



  @Data
  public static class CaConfigProperties {
    /** The URL at the CA receiving request to get information about a registered user */
    private String getUserUrl;

    /** The URL at the CA receiving request to register new users at the CA */
    private String registerUserUrl;

    /** The URL at the CA receiving request to register a CSR for a new certificate request */
    private String registerCsrUrl;

    /** The URL the user is redirected to at the CA in order to complete authentication and issue a certificate based on the registered CSR */
    private String certificateIssuanceUrl;

    /** Set to true to allow new user registration at the CA if the requested user attribute contains sufficient data about the user */
    private boolean allowNewUserRegistration;

    /** The key type being generated for the user at each instant of signing */
    private String keyGenType;

    /** The algorithm used to sign the CSR with the user generated key */
    private String certReqAlgo;

    /** The certificate chain used by the CA that issues the certificate for the user */
    private List<Resource> caCertificateChain;

    /** Level of assurance assigned to assertion objects based on this authentication process (to be compared with the sign request requirements) */
    private String loa;

  }

}
