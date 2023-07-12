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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import lombok.extern.slf4j.Slf4j;
import se.sunet.edusign.harica.certificate.HaricaCAKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.core.config.AbstractHandlerFactory;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Factory for creating {@link HaricaCAKeyAndCertificateHandler} instances.
 */
@Slf4j
public class HaricaKeyAndCertificateHandlerFactory extends AbstractHandlerFactory<KeyAndCertificateHandler> {


  @Nonnull @Override protected KeyAndCertificateHandler createHandler(
    @Nullable HandlerConfiguration<KeyAndCertificateHandler> configuration, @Nullable BeanLoader beanLoader)
    throws IllegalArgumentException {

    if (!HaricaKeyAndCertificateHandlerConfiguration.class.isInstance(configuration)) {
      throw new IllegalArgumentException(
        "Unknown configuration object supplied - " + configuration.getClass().getSimpleName());
    }
    final HaricaKeyAndCertificateHandlerConfiguration conf =
      HaricaKeyAndCertificateHandlerConfiguration.class.cast(configuration);

    return this.createHandler();
  }

  private KeyAndCertificateHandler createHandler() {
    return new HaricaCAKeyAndCertificateHandler();
  }

  @Override protected Class<KeyAndCertificateHandler> getHandlerType() {
    return null;
  }

}
