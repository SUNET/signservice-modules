package se.sunet.edusign.harica.certificate.config;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.config.AbstractKeyAndCertificateHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Test cases for SimpleKeyAndCertificateHandlerFactory.
 */
public class HaricaKeyAndCertificateHandlerFactoryTest {

  @BeforeAll
  public static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }


  @Test
  void testFactory() throws Exception {
    HandlerConfiguration<KeyAndCertificateHandler> config = new HaricaKeyAndCertificateHandlerConfiguration();
    final HaricaKeyAndCertificateHandlerFactory factory = new HaricaKeyAndCertificateHandlerFactory();
    KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertNotNull(handler);
  }

  @Test
  public void testBadConfigType() throws Exception {
    HandlerConfiguration<KeyAndCertificateHandler> config = new AbstractKeyAndCertificateHandlerConfiguration() {
      @Override
      protected String getDefaultFactoryClass() {
        return "dummy";
      }
    };
    final HaricaKeyAndCertificateHandlerFactory factory = new HaricaKeyAndCertificateHandlerFactory();
    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown configuration object supplied - ");
  }



}
