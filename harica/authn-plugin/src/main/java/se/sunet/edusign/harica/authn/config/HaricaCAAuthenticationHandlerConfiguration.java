package se.sunet.edusign.harica.authn.config;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

import com.nimbusds.jose.JWSAlgorithm;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Getter;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;

/**
 * Base class for configuring CA authentication handlers using the Harica API.
 */
public class HaricaCAAuthenticationHandlerConfiguration
    extends AbstractHandlerConfiguration<AuthenticationHandler> {

  /** HTTP connect timeout in milliseconds */
  @Getter
  int connectTimeout;

  /** HTTP read timeout in milliseconds */
  @Getter
  int readTimeout;

  /** Optional Http Proxy configuration data */
  @Getter
  HttpProxyConfiguration httpProxyConfiguration;

  /** Credentials for signing requests to the CA */
  @Getter
  PrivateKey requestSigningCredential;

  /** Algorithm used to sign request to CA */
  @Getter
  JWSAlgorithm requestSigningAlgorithm;

  /** Trusted certificate for validating certificate result tokens from CA */
  @Getter
  PublicKey trustedCaTokenVerificationKey;

  /**
   * URL configuration settings for this SP specifying URL end points provided by this service to communicate with the
   * CA
   */
  @Getter
  SpUrlConfiguration spUrlConfiguration;

  /** Configuration data that is used by the handler to interact with the CA and to process its result */
  @Getter
  CaConfiguration caConfiguration;

  /**
   * The name of the attribute specified in sign request as the ID of attributes used to provide the e-mail of the
   * signer
   */
  @Getter
  String emailAdressSource;

  /**
   * The name of the attribute specified in sign request as the ID of attributes used to provide the unique identifier
   * of the signer
   */
  @Getter
  String uniqueIdentifierSource;

  /**
   * The name of the attribute specified in sign request as the ID of attributes used to provide the surname of the
   * signer
   */
  @Getter
  String surnameSource;

  /**
   * The name of the attribute specified in sign request as the ID of attributes used to provide the given name of the
   * signer
   */
  @Getter
  String givenNameSource;

  public void setConnectTimeout(final int connectTimeout) {
    this.connectTimeout = connectTimeout;
  }

  public void setReadTimeout(final int readTimeout) {
    this.readTimeout = readTimeout;
  }

  public void setSpUrlConfiguration(@Nonnull final SpUrlConfiguration spUrlConfiguration) {
    this.spUrlConfiguration = Objects.requireNonNull(spUrlConfiguration, "spUrlConfiguration must not be null");
  }

  public void setCaConfiguration(@Nonnull final CaConfiguration caConfiguration) {
    this.caConfiguration = Objects.requireNonNull(caConfiguration, "caConfiguration must not be null");
  }

  public void setHttpProxyConfiguration(@Nullable final HttpProxyConfiguration httpProxyConfiguration) {
    this.httpProxyConfiguration = httpProxyConfiguration;
  }

  public void setRequestSigningCredential(@Nonnull final PrivateKey requestSigningCredential) {
    this.requestSigningCredential = Objects.requireNonNull(requestSigningCredential,
        "requestSigningCredential must not be null");
  }

  public void setRequestSigningAlgorithm(@Nonnull final JWSAlgorithm requestSigningAlgorithm) {
    this.requestSigningAlgorithm = Objects.requireNonNull(requestSigningAlgorithm,
        "requestSigningAlgorithm must not be null");
  }

  public void setTrustedCaTokenVerificationKey(@Nonnull final PublicKey trustedCaTokenVerificationKey) {
    this.trustedCaTokenVerificationKey = Objects.requireNonNull(trustedCaTokenVerificationKey,
        "trustedCaTokenSignerCert must not be null");
  }

  public void setEmailAdressSource(@Nullable final String emailAdressSource) {
    this.emailAdressSource = emailAdressSource;
  }

  public void setUniqueIdentifierSource(@Nullable final String uniqueIdentifierSource) {
    this.uniqueIdentifierSource = uniqueIdentifierSource;
  }

  public void setSurnameSource(@Nullable final String surnameSource) {
    this.surnameSource = surnameSource;
  }

  public void setGivenNameSource(@Nullable final String givenNameSource) {
    this.givenNameSource = givenNameSource;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getDefaultFactoryClass() {
    return HaricaCAAuthenticationFactory.class.getName();
  }

}
