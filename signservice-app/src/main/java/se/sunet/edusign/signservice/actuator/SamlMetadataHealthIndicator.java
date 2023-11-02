package se.sunet.edusign.signservice.actuator;

import java.util.List;

import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.resolver.ResolverException;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;

/**
 * If there is a {@link MetadataProvider} bean available, this health indicator will check to see that the provider is
 * functioning.
 */
@Component
@Slf4j
public class SamlMetadataHealthIndicator implements HealthIndicator {

  /** The metadata provider to monitor. */
  @Setter
  @Autowired(required = false)
  private MetadataProvider metadata;

  /** {@inheritDoc} */
  @Override
  public Health health() {
    if (this.metadata == null) {
      return Health.up().build();
    }

    try {
      final List<EntityDescriptor> idps = this.metadata.getIdentityProviders();
      if (idps.isEmpty()) {
        final String msg = "No valid IdP metadata found";
        log.warn("{}", msg);
        return Health.outOfService()
            .withDetail("reason", msg)
            .build();
      }
      else {
        return Health.up().withDetail("available-idps", idps.size()).build();
      }
    }
    catch (final ResolverException e) {
      log.warn("Failed to list IdP:s from SAML metadata", e);
      return Health.outOfService()
          .withDetail("reason", "Failed to get SAML metadata")
          .withException(e)
          .build();
    }
  }

}
