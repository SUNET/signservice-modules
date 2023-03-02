package se.sunet.edusign.signservice.config;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;

import se.sunet.edusign.signservice.extensions.RedisReplayCheckerStorageContainer;
import se.swedenconnect.signservice.storage.impl.InMemoryReplayCheckerStorageContainer;
import se.swedenconnect.signservice.storage.impl.ReplayCheckerStorageContainer;

/**
 * Configuration for SignService.
 */
@Configuration
public class SignServiceConfiguration {
  
  @Value("${signservice.validation-config.max-message-age:PT6M}")
  private Duration maxMessageAge;
  
  @ConditionalOnProperty(name = "spring.session.store-type", havingValue = "redis")
  @Bean
  RedisTemplate<String, Long> replayRedisTemplate(final RedisConnectionFactory connectionFactory) {
    RedisTemplate<String, Long> template = new RedisTemplate<>();
    template.setConnectionFactory(connectionFactory);
    return template;
  }

  @ConditionalOnProperty(name = "spring.session.store-type", havingValue = "none", matchIfMissing = true)
  @Bean("signservice.ReplayCheckerStorageContainer")
  ReplayCheckerStorageContainer inMemoryReplayCheckerStorageContainer() {
    final InMemoryReplayCheckerStorageContainer container = new InMemoryReplayCheckerStorageContainer("in-replay-storage");
    // Twice the message age is enough
    container.setElementLifetime(this.maxMessageAge.plus(this.maxMessageAge));
    return container; 
  }
  
  @ConditionalOnProperty(name = "spring.session.store-type", havingValue = "redis")
  @Bean("signservice.ReplayCheckerStorageContainer")
  ReplayCheckerStorageContainer redisReplayCheckerStorageContainer(final RedisTemplate<String, Long> redisTemplate) {
    final RedisReplayCheckerStorageContainer container = new RedisReplayCheckerStorageContainer("redis-replay-storage", redisTemplate);
    container.setElementLifetime(this.maxMessageAge.plus(this.maxMessageAge));
    return container;
  }

  @Bean
  @ConfigurationProperties(prefix = "tomcat.ajp")
  TomcatAjpConfigurationProperties tomcatAjpConfigurationProperties() {
    return new TomcatAjpConfigurationProperties();
  }

}
