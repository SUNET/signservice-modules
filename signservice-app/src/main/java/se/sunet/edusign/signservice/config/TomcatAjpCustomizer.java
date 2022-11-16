package se.sunet.edusign.signservice.config;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.ajp.AbstractAjpProtocol;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;

import lombok.Setter;

/**
 * Configuration settings for Tomcat AJP.
 */
@Component
@ConditionalOnProperty(name = "tomcat.ajp.enabled", havingValue = "true")
public class TomcatAjpCustomizer implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

  @Autowired
  @Setter
  private TomcatAjpConfigurationProperties ajp;

  /** {@inheritDoc} */
  @Override
  public void customize(final TomcatServletWebServerFactory factory) {

    if (this.ajp.isEnabled()) {
      Connector ajpConnector = new Connector("AJP/1.3");
      ajpConnector.setPort(this.ajp.getPort());
      ajpConnector.setAllowTrace(false);
      ajpConnector.setScheme("http");
      ajpConnector.setProperty("address", "0.0.0.0");
      ajpConnector.setProperty("allowedRequestAttributesPattern", ".*");

      final AbstractAjpProtocol<?> protocol = (AbstractAjpProtocol<?>) ajpConnector.getProtocolHandler();
      if (this.ajp.isSecretRequired()) {
        ajpConnector.setSecure(true);
        protocol.setSecretRequired(true);
        protocol.setSecret(this.ajp.getSecret());
      }
      else {
        ajpConnector.setSecure(false);
        protocol.setSecretRequired(false);
      }

      factory.addAdditionalTomcatConnectors(ajpConnector);
    }

  }

}
