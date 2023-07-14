package se.sunet.edusign.harica.certificate.config.spring;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import se.sunet.edusign.harica.certificate.HaricaCAKeyAndCertificateHandler;
import se.sunet.edusign.harica.certificate.config.HaricaKeyAndCertificateHandlerConfiguration;
import se.sunet.edusign.harica.certificate.config.HaricaKeyAndCertificateHandlerFactory;

/**
 * Spring @Configuration class for providing the {@link HaricaCAKeyAndCertificateHandler} as a bean
 */
@Configuration
public class CAKeyAndCertHandlerBeanConfiguration {

  @Bean(name = "signservice.HaricaCAKeyAndCertificateHandler")
  HaricaCAKeyAndCertificateHandler haricaCAKeyAndCertificateHandler() {
    HaricaKeyAndCertificateHandlerFactory factory = new HaricaKeyAndCertificateHandlerFactory();
    HaricaKeyAndCertificateHandlerConfiguration configuration = new HaricaKeyAndCertificateHandlerConfiguration();
    return (HaricaCAKeyAndCertificateHandler) factory.create(configuration);
  }
}
