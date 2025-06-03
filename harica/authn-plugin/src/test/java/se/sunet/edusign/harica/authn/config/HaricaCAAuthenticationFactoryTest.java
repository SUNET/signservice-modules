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

import org.junit.jupiter.api.Test;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test cases for SamlAuthenticationHandlerFactory.
 */
public class HaricaCAAuthenticationFactoryTest {

  @Test
  public void testMissingConfig() {
    final HaricaCAAuthenticationFactory factory = new HaricaCAAuthenticationFactory();
    assertThatThrownBy(() -> {
      factory.create(null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("Missing configuration for creating AuthenticationHandler instances");
  }

  @Test
  public void testOtherConfig() {
    final HandlerConfiguration<AuthenticationHandler> conf = new AbstractHandlerConfiguration<AuthenticationHandler>() {

      @Override
      protected String getDefaultFactoryClass() {
        return "dummy";
      }
    };
    final HaricaCAAuthenticationFactory factory = new HaricaCAAuthenticationFactory();
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown configuration object supplied - ");
  }

  @SuppressWarnings("unused")
  private static class HaricaCAAuthenticationFactory2 extends HaricaCAAuthenticationFactory {

    public Class<AuthenticationHandler> handler() {
      return this.getHandlerType();
    }
  }

}
