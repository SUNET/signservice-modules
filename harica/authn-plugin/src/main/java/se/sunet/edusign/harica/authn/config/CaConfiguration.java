package se.sunet.edusign.harica.authn.config;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import javax.annotation.Nonnull;

import lombok.Getter;

/**
 * Configuration data that is used by the handler to interact with the CA and to process its result
 */
public class CaConfiguration {

  /** The URL at the CA receiving request to get information about a registered user */
  @Getter
  private String getUserUrl;

  /** The URL at the CA receiving request to register new users at the CA */
  @Getter
  private String registerUserUrl;

  /** The URL at the CA receiving request to register a CSR for a new certificate request */
  @Getter
  private String registerCsrUrl;

  /** The URL the user is redirected to at the CA in order to complete authentication and issue a certificate based on the registered CSR */
  @Getter
  private String certificateIssuanceUrl;

  /** Set to true to allow new user registration at the CA if the requested user attribute contains sufficient data about the user */
  @Getter
  private boolean allowNewUserRegistration;

  /** The key type being generated for the user at each instant of signing */
  @Getter
  private String keyGenType;

  /** The algorithm used to sign the CSR with the user generated key */
  @Getter
  private String certReqAlgo;

  /** The certificate chain used by the CA that issues the certificate for the user */
  @Getter
  private List<X509Certificate> caCertificateChain;

  /** Level of assurance assigned to assertion objects based on this authentication process (to be compared with the sign request requirements) */
  @Getter
  private String loa;

  public void setGetUserUrl(@Nonnull final String getUserUrl) {
    this.getUserUrl = Objects.requireNonNull(getUserUrl, "getUserUrl must not be null");
  }

  public void setRegisterUserUrl(@Nonnull final String registerUserUrl) {
    this.registerUserUrl = Objects.requireNonNull(registerUserUrl, "registerUserUrl must not be null");
  }

  public void setRegisterCsrUrl(@Nonnull final String registerCsrUrl) {
    this.registerCsrUrl = Objects.requireNonNull(registerCsrUrl, "registerCsrUrl must not be null");
  }

  public void setCertificateIssuanceUrl(@Nonnull final String certificateIssuanceUrl) {
    this.certificateIssuanceUrl = Objects.requireNonNull(certificateIssuanceUrl, "certificateIssuanceUrl must not be null");
  }

  public void setAllowNewUserRegistration(final boolean allowNewUserRegistration) {
    this.allowNewUserRegistration = allowNewUserRegistration;
  }

  public void setKeyGenType(@Nonnull final String keyGenType) {
    this.keyGenType = Objects.requireNonNull(keyGenType, "keyGenType must not be null");
  }

  public void setCertReqAlgo(@Nonnull final String certReqAlgo) {
    this.certReqAlgo = Objects.requireNonNull(certReqAlgo, "certReqAlgo must not be null");
  }

  public void setCaCertificateChain(@Nonnull final List<X509Certificate> caCertificateChain) {
    this.caCertificateChain = Objects.requireNonNull(caCertificateChain, "caCertificateChain must not be null");
  }

  public void setLoa(@Nonnull final String loa) {
    this.loa = Objects.requireNonNull(loa, "Level of assurance must not be null");
  }
}
