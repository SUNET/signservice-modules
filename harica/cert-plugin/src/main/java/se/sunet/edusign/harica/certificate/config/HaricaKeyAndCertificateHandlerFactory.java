package se.sunet.edusign.harica.certificate.config;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.sunet.edusign.harica.certificate.HaricaCAKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.core.config.AbstractHandlerFactory;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Factory for creating {@link HaricaCAKeyAndCertificateHandler} instances.
 */
public class HaricaKeyAndCertificateHandlerFactory extends AbstractHandlerFactory<KeyAndCertificateHandler> {

  @Nonnull
  @Override
  protected KeyAndCertificateHandler createHandler(
      @Nullable HandlerConfiguration<KeyAndCertificateHandler> configuration, @Nullable BeanLoader beanLoader)
      throws IllegalArgumentException {

    if (!HaricaKeyAndCertificateHandlerConfiguration.class.isInstance(configuration)) {
      throw new IllegalArgumentException(
          "Unknown configuration object supplied - " + configuration.getClass().getSimpleName());
    }

    return this.createHandler();
  }

  private KeyAndCertificateHandler createHandler() {
    return new HaricaCAKeyAndCertificateHandler();
  }

  @Override
  protected Class<KeyAndCertificateHandler> getHandlerType() {
    return KeyAndCertificateHandler.class;
  }

}
