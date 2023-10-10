package se.sunet.edusign.harica.authn.config;

import lombok.Data;

/**
 * HTTP proxy configuration data
 */
@Data
public class HttpProxyConfiguration {

  /**
   * The proxy host.
   */
  private String host;

  /**
   * The proxy port.
   */
  private int port;

  /**
   * The proxy password (optional).
   */
  private String password;

  /**
   * The proxy username (optional).
   */
  private String userName;
}
