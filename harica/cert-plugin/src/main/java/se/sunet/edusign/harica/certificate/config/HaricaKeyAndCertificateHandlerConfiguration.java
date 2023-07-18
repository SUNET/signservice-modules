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

import se.sunet.edusign.harica.certificate.HaricaCAKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.config.AbstractKeyAndCertificateHandlerConfiguration;

/**
 * Configuration for {@link HaricaCAKeyAndCertificateHandler}.
 *
 * This handler currently has no configuration parameters, but if needed, it goes here.
 */
public class HaricaKeyAndCertificateHandlerConfiguration extends AbstractKeyAndCertificateHandlerConfiguration {

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getDefaultFactoryClass() {
    return HaricaKeyAndCertificateHandlerFactory.class.getName();
  }

}
