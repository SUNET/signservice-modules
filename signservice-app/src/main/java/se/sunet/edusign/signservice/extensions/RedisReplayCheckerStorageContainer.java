/*
 * Copyright 2023 Sweden Connect
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
package se.sunet.edusign.signservice.extensions;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import se.swedenconnect.signservice.storage.impl.ReplayCheckerStorageContainer;

/**
 * A {@link ReplayCheckerStorageContainer} backed by Redis.
 * 
 * @author Martin Lindström
 */
public class RedisReplayCheckerStorageContainer implements ReplayCheckerStorageContainer {

  /** Default element lifetime. */
  public static final Duration DEFAULT_ELEMENT_LIFETIME = Duration.ofMinutes(10);
  
  private static final String REDIS_KEY_PREFIX = "replay-";

  /** The container name. */
  private final String name;

  /** The Redis template object. */
  private final RedisTemplate<String, Long> redisTemplate;

  /** The Redis hash operations object. */
//  private HashOperations<String, String, Long> operations;

  /** The Redis operations object. */
  private ValueOperations<String, Long> operations;

  /** Amount of time elements are kept. */
  private Duration elementLifetime;

  /**
   * Constructor.
   * 
   * @param name the name of the container
   */
  public RedisReplayCheckerStorageContainer(final String name, final RedisTemplate<String, Long> redisTemplate) {
    this.name = Objects.requireNonNull(name, "name must not be null");
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    //this.operations = this.redisTemplate.opsForHash();    
    this.operations = this.redisTemplate.opsForValue();
    
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return this.name;
  }

  /** {@inheritDoc} */
  @Override
  public void put(final String id, final Long data) {
    this.operations.set(REDIS_KEY_PREFIX + id, data, this.getElementLifetime());
  }

  /** {@inheritDoc} */
  @Override
  public Long get(final String id) {
    return this.operations.get(REDIS_KEY_PREFIX + id);
  }

  /** {@inheritDoc} */
  @Override
  public void remove(final String id) {
    this.operations.getAndDelete(REDIS_KEY_PREFIX + id);
  }

  /** {@inheritDoc} */
  @Override
  public Duration getElementLifetime() {
    return Optional.ofNullable(this.elementLifetime).orElseGet(() -> DEFAULT_ELEMENT_LIFETIME);
  }

  /**
   * Assigns the element lifetime.
   * 
   * @param elementLifetime the element lifetime
   */
  public void setElementLifetime(final Duration elementLifetime) {
    this.elementLifetime = elementLifetime;
  }

}
