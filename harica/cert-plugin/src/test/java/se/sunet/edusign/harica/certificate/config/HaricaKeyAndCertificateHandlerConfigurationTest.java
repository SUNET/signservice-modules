package se.sunet.edusign.harica.certificate.config;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for SimpleKeyAndCertificateHandlerConfiguration.
 */
public class HaricaKeyAndCertificateHandlerConfigurationTest {

  @Test
  public void testFactory() {
    final HaricaKeyAndCertificateHandlerConfiguration config = new HaricaKeyAndCertificateHandlerConfiguration();
    Assertions.assertEquals(HaricaKeyAndCertificateHandlerFactory.class.getName(), config.getFactoryClass());
  }



}
