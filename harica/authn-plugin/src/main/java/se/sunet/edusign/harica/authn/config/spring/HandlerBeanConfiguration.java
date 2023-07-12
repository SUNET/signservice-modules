package se.sunet.edusign.harica.authn.config.spring;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import se.sunet.edusign.harica.authn.HaricaCAAuthenticationHandler;

/**
 * Spring @Configuration class for providning the {@link HaricaCAAuthenticationHandler} as a bean
 */
@Configuration
public class HandlerBeanConfiguration {


  @Bean
  HaricaCAAuthenticationHandler haricaCAAuthenticationHandler() {
    return null;
  }

}
