package se.sunet.edusign.signservice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.security.credential.container.PkiCredentialContainerException;
import se.swedenconnect.signservice.storage.impl.InMemoryReplayCheckerStorageContainer;

/**
 * Responsible of handling scheduled tasks.
 */
@Service
@Slf4j
public class SignServiceScheduler {

  /** The application context. */
  @Autowired
  @Setter
  private ApplicationContext applicationContext;

  /** The replay storage that we use. */
  @Autowired(required = false)
  @Setter
  private InMemoryReplayCheckerStorageContainer replayStorage;

  /** Key provider that may have to be "cleaned". */
  @Autowired(required = false)
  @Setter
  private PkiCredentialContainer keyProvider;

  /**
   * Cleans the replay storage.
   */
  @Scheduled(fixedDelay = 600000L)
  public void clearReplayStorage() {
    if (this.replayStorage != null) {
      this.replayStorage.cleanup();
    }
  }

  /**
   * Cleans the key provider from dangling private keys.
   */
  @Scheduled(initialDelay = 600000L, fixedDelay = 18000000L)
  public void cleanKeyProvider() {
    if (this.keyProvider == null) {
      try {
        this.keyProvider.cleanup();
      }
      catch (final PkiCredentialContainerException e) {
        log.warn("Error during clean up of key provider - {}", e.getMessage(), e);
      }
    }
  }

}
