package se.sunet.edusign.signservice.actuator;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.stereotype.Component;

import lombok.Setter;
import se.swedenconnect.signservice.application.SignServiceEngineManager;
import se.swedenconnect.signservice.engine.SignServiceEngine;

/**
 * Displays information about the SignService setup.
 */
@Component
public class SignServiceInfoContributor implements InfoContributor {

  @Setter
  @Autowired
  private SignServiceEngineManager manager;

  @Override
  public void contribute(final Info.Builder builder) {

    // TODO: We should extend the engine interface to give more information ...
    final List<String> info = new ArrayList<>();
    for (final SignServiceEngine engine : this.manager.getEngines()) {
      info.add(engine.getName());
    }
    builder.withDetail("engines", info);
  }

}
