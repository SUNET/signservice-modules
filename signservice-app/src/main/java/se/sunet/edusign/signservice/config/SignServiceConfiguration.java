package se.sunet.edusign.signservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import se.swedenconnect.signservice.storage.impl.InMemoryReplayCheckerStorageContainer;

/**
 * Configuration for SignService.
 */
@Configuration
public class SignServiceConfiguration {

  @Bean
  public InMemoryReplayCheckerStorageContainer inMemoryReplayCheckerStorageContainer() {
    return new InMemoryReplayCheckerStorageContainer("replay-storage");
  }

  @Bean
  @ConfigurationProperties(prefix = "tomcat.ajp")
  public TomcatAjpConfigurationProperties tomcatAjpConfigurationProperties() {
    return new TomcatAjpConfigurationProperties();
  }

}
