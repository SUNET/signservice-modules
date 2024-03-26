package se.sunet.edusign.signservice.config;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.session.MapSessionRepository;

import se.sunet.edusign.signservice.extensions.RedisReplayCheckerStorageContainer;
import se.swedenconnect.signservice.config.SignServiceConfigurationProperties;
import se.swedenconnect.signservice.core.config.ValidationConfiguration;
import se.swedenconnect.signservice.storage.impl.InMemoryReplayCheckerStorageContainer;
import se.swedenconnect.signservice.storage.impl.ReplayCheckerStorageContainer;

/**
 * Configuration for SignService.
 */
@Configuration
public class SignServiceConfiguration {

  /** The SignService configuration properties. */
  private final SignServiceConfigurationProperties properties;

  public SignServiceConfiguration(final SignServiceConfigurationProperties properties) {
    this.properties = properties;
  }

  @Bean
  @ConfigurationProperties(prefix = "tomcat.ajp")
  TomcatAjpConfigurationProperties tomcatAjpConfigurationProperties() {
    return new TomcatAjpConfigurationProperties();
  }

  @Bean("signservice.ReplayCheckerLifetime")
  Duration replayCheckerElementLifetime() {
    final Duration maxMessageAge = Optional.ofNullable(this.properties.getValidationConfig())
        .map(ValidationConfiguration::getMaxMessageAge)
        .orElseGet(() -> Duration.ofMinutes(6));
    return maxMessageAge.plus(maxMessageAge);
  }

  @Configuration
  @ConditionalOnProperty(name = "spring.session.store-type", havingValue = "none", matchIfMissing = true)
  @EnableAutoConfiguration(exclude = { RedisAutoConfiguration.class, RedisRepositoriesAutoConfiguration.class })
  public static class SignServiceNoRedisConfiguration {

    @Bean("signservice.ReplayCheckerStorageContainer")
    ReplayCheckerStorageContainer inMemoryReplayCheckerStorageContainer(
        @Qualifier("signservice.ReplayCheckerLifetime") Duration replayCheckerElementLifetime) {
      final InMemoryReplayCheckerStorageContainer container =
          new InMemoryReplayCheckerStorageContainer("in-replay-storage");
      // Twice the message age is enough
      container.setElementLifetime(replayCheckerElementLifetime);
      return container;
    }

    @Bean
    MapSessionRepository inMemorySessionRepository() {
      return new MapSessionRepository(new ConcurrentHashMap<>());
    }

  }

  @ConditionalOnProperty(name = "spring.session.store-type", havingValue = "redis")
  @Configuration
  public static class SignServiceRedisConfiguration {

    @Bean
    RedisTemplate<String, Long> replayRedisTemplate(final RedisConnectionFactory connectionFactory) {
      RedisTemplate<String, Long> template = new RedisTemplate<>();
      template.setConnectionFactory(connectionFactory);
      return template;
    }

    @Bean("signservice.ReplayCheckerStorageContainer")
    ReplayCheckerStorageContainer redisReplayCheckerStorageContainer(final RedisTemplate<String, Long> redisTemplate,
        @Qualifier("signservice.ReplayCheckerLifetime") Duration replayCheckerElementLifetime) {
      final RedisReplayCheckerStorageContainer container =
          new RedisReplayCheckerStorageContainer("redis-replay-storage", redisTemplate);
      container.setElementLifetime(replayCheckerElementLifetime);
      return container;
    }

  }

}
