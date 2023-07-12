package se.sunet.edusign.harica.authn.config.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;
import se.sunet.edusign.harica.authn.HaricaCAAuthenticationHandler;

/**
 * Configuration properties for creating a {@link HaricaCAAuthenticationHandler} bean
 */
@Configuration
@Data
@ConfigurationProperties(prefix = "harica-authn")
public class HaricaCAAuthHandlerConfigurationProperties {

  

}
