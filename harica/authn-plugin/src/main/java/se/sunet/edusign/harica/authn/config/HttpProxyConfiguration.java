/*
 * Copyright 2023 Agency for Digital Government (DIGG)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
