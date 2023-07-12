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
package se.sunet.edusign.harica.certificate.config;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.config.AbstractKeyAndCertificateHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Test cases for SimpleKeyAndCertificateHandlerFactory.
 */
public class HaricaKeyAndCertificateHandlerFactoryTest {

  @BeforeAll
  public static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }


  @Test
  void testFactory() throws Exception {
    HandlerConfiguration<KeyAndCertificateHandler> config = new HaricaKeyAndCertificateHandlerConfiguration();
    final HaricaKeyAndCertificateHandlerFactory factory = new HaricaKeyAndCertificateHandlerFactory();
    KeyAndCertificateHandler handler = factory.create(config);
    Assertions.assertNotNull(handler);
  }

  @Test
  public void testBadConfigType() throws Exception {
    HandlerConfiguration<KeyAndCertificateHandler> config = new AbstractKeyAndCertificateHandlerConfiguration() {
      @Override
      protected String getDefaultFactoryClass() {
        return "dummy";
      }
    };
    final HaricaKeyAndCertificateHandlerFactory factory = new HaricaKeyAndCertificateHandlerFactory();
    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown configuration object supplied - ");
  }



}
