/*
 * Copyright 2022 Sweden Connect
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

import java.util.Objects;

import javax.annotation.Nonnull;

import lombok.Getter;

/**
 * URL configuration settings for this SP specifying URL end points provided by this service to communicate with the CA.
 */
public class SpUrlConfiguration {

  /**
   * The application base URL. Must not end with a slash. The base URL consists of the protocol, host and context path.
   */
  @Getter
  private String baseUrl;

  /**
   * The path to where the SP receives Certificate issuing responses. Relative to {@code baseUrl}.
   */
  @Getter
  private String certificateReturnPath;

  /**
   * Assigns the application base URL. Must not end with a slash.
   *
   * @param baseUrl the application base URL
   */
  public void setBaseUrl(@Nonnull final String baseUrl) {
    this.baseUrl = Objects.requireNonNull(baseUrl, "baseUrl must not be null");
    if (this.baseUrl.endsWith("/")) {
      throw new IllegalArgumentException("The baseUrl must not end with a '/'");
    }
  }

  /**
   * Assigns the path to where the SP receives SAML responses. Relative to {@code baseUrl}.
   *
   * @param certificateReturnPath the path for receiving SAML responses
   */
  public void setCertificateReturnPath(@Nonnull final String certificateReturnPath) {
    this.certificateReturnPath =
        Objects.requireNonNull(certificateReturnPath, "assertionConsumerPath must not be null");
    if (!this.certificateReturnPath.startsWith("/")) {
      throw new IllegalArgumentException("The assertionConsumerPath must begin with a '/'");
    }
  }


  /** {@inheritDoc} */
  @Override
  public String toString() {
    StringBuffer sb = new StringBuffer("base-url='")
        .append(this.baseUrl)
        .append("', assertion-consumer-path='")
        .append(this.certificateReturnPath);
    return sb.toString();
  }

}
