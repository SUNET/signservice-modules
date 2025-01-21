package se.sunet.edusign.harica.authn.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.CredentialsProvider;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import se.sunet.edusign.harica.authn.HaricaCAAuthenticationHandler;
import se.sunet.edusign.harica.authn.service.BackChannelRequestSigner;
import se.sunet.edusign.harica.authn.service.CARequestConnector;
import se.sunet.edusign.harica.authn.service.CertificateRequestFactory;
import se.sunet.edusign.harica.authn.service.CertificateRequestService;
import se.sunet.edusign.harica.authn.service.UserRegistrationService;
import se.sunet.edusign.harica.authn.service.token.ResponseParser;
import se.sunet.edusign.harica.authn.service.token.TokenCredential;
import se.sunet.edusign.harica.authn.service.token.TokenValidator;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.credential.container.InMemoryPkiCredentialContainer;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.core.config.AbstractHandlerFactory;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.util.List;
import java.util.Objects;

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

      X509CertificateHolder caCertHolder =
          new JcaX509CertificateHolder(conf.getCaConfiguration().getCaCertificateChain().get(0));

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
          final BasicCredentialsProvider credentialsPovider = new BasicCredentialsProvider();
          credentialsPovider.setCredentials(new AuthScope(proxy), new UsernamePasswordCredentials(
              proxyConfig.getUserName(), proxyConfig.getPassword().toCharArray()));
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
