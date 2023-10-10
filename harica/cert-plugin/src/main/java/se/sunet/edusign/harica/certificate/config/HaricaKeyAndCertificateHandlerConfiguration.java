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
