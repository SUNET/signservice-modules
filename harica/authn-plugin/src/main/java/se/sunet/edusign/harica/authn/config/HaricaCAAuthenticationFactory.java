/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.sunet.edusign.harica.authn.config;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.util.List;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;

import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.credential.container.InMemoryPkiCredentialContainer;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.sunet.edusign.harica.authn.HaricaCAAuthenticationHandler;
import se.swedenconnect.signservice.core.config.AbstractHandlerFactory;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.sunet.edusign.harica.authn.service.BackChannelRequestSigner;
import se.sunet.edusign.harica.authn.service.CARequestConnector;
import se.sunet.edusign.harica.authn.service.CertificateRequestFactory;
import se.sunet.edusign.harica.authn.service.CertificateRequestService;
import se.sunet.edusign.harica.authn.service.UserRegistrationService;
import se.sunet.edusign.harica.authn.service.token.ResponseParser;
import se.sunet.edusign.harica.authn.service.token.TokenCredential;
import se.sunet.edusign.harica.authn.service.token.TokenValidator;

/**
 * Base class for factories creating Harica CA authentication handlers.
 */
public class HaricaCAAuthenticationFactory extends AbstractHandlerFactory<AuthenticationHandler> {

  /** {@inheritDoc} */
  @Override
  protected AuthenticationHandler createHandler(
    @Nonnull final HandlerConfiguration<AuthenticationHandler> configuration, @Nullable final BeanLoader beanLoader)
    throws IllegalArgumentException {

    Objects.requireNonNull(configuration, "Missing configuration for creating AuthenticationHandler instances");

    if (!HaricaCAAuthenticationHandlerConfiguration.class.isInstance(configuration)) {
      throw new IllegalArgumentException(
        "Unknown configuration object supplied - " + configuration.getClass().getSimpleName());
    }
    final HaricaCAAuthenticationHandlerConfiguration conf =
      HaricaCAAuthenticationHandlerConfiguration.class.cast(configuration);

    // Create the handler
    //
    return this.createHandler(conf);
  }

  /**
   * Creates the Harica CA authentication handler.
   *
   * @return a SAML authention handler
   */
  private HaricaCAAuthenticationHandler createHandler(HaricaCAAuthenticationHandlerConfiguration conf) {

    try {
      CARequestConnector caRequestConnector = new CARequestConnector(
        getHttpClient(conf.getHttpProxyConfiguration()), conf.getConnectTimeout(), conf.getReadTimeout());

      boolean ecSigner = conf.getRequestSigningAlgorithm().getName().startsWith("ES");
      JWSSigner signer = ecSigner
        ? new ECDSASigner((ECPrivateKey) conf.getRequestSigningCredential())
        : new RSASSASigner(conf.getRequestSigningCredential());

      BackChannelRequestSigner backChannelRequestSigner = new BackChannelRequestSigner(signer,
        conf.requestSigningAlgorithm);

      TokenCredential trustedCredential = new TokenCredential(conf.getTrustedCaTokenVerificationKey());

      X509CertificateHolder caCertHolder = new JcaX509CertificateHolder(conf.getCaConfiguration().getCaCertificateChain().get(0));

      return new HaricaCAAuthenticationHandler(
        conf.getSpUrlConfiguration(),
        conf.getCaConfiguration(),
        new UserRegistrationService(caRequestConnector, backChannelRequestSigner, conf.getCaConfiguration()),
        new TokenValidator(trustedCredential),
        new ResponseParser(new ObjectMapper(), CertificateFactory.getInstance("X.509")),
        new CertificateRequestService(caRequestConnector, backChannelRequestSigner, conf.getCaConfiguration()),
        new InMemoryPkiCredentialContainer("BC"),
        new CertificateRequestFactory(caCertHolder, List.of("http://example.com/crl"), "http://example.com/ocsp"),
        AlgorithmRegistrySingleton.getInstance()
      );
    }
    catch (JOSEException | CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected Class<AuthenticationHandler> getHandlerType() {
    return AuthenticationHandler.class;
  }

  private CloseableHttpClient getHttpClient(final HttpProxyConfiguration proxyConfig) {
    try {
      final HttpClientBuilder builder = HttpClientBuilder.create();
      if (proxyConfig != null && proxyConfig.getHost() != null) {
        final HttpHost proxy = new HttpHost(proxyConfig.getHost(), proxyConfig.getPort());
        builder.setProxy(proxy);
        if (proxyConfig.getUserName() != null) {
          CredentialsProvider credentialsPovider = new BasicCredentialsProvider();
          credentialsPovider.setCredentials(new AuthScope(proxy), new UsernamePasswordCredentials(
            proxyConfig.getUserName(), proxyConfig.getPassword()));
          builder.setDefaultCredentialsProvider(credentialsPovider);
        }
      }
      return builder
        .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
        .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
        .build();
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to initialize HttpClient", e);
    }
  }

}
