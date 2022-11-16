package se.sunet.edusign.signservice.config;

import lombok.Getter;
import lombok.Setter;

/**
 * Configuration properties for Tomcat AJP.
 */
public class TomcatAjpConfigurationProperties {

  /** Is AJP enabled? */
  @Getter
  @Setter
  private boolean enabled = false;

  /** The Tomcat AJP port. */
  @Getter
  @Setter
  private int port = 8009;

  /** AJP secret. */
  @Getter
  @Setter
  private String secret;

  /** Is AJP secret required? */
  @Getter
  @Setter
  private boolean secretRequired = false;

}
