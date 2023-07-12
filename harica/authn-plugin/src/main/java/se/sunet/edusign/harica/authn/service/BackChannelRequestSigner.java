package se.sunet.edusign.harica.authn.service;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;

import lombok.extern.slf4j.Slf4j;

/**
 * Create JWS tokens
 */
@Slf4j
public class BackChannelRequestSigner {

  /** Signer used to sign data */
  private final JWSSigner signer;
  /** algorithm used to sign data */
  private final JWSAlgorithm algorithm;

  /**
   * Constructor
   *
   * @param signer signer used to sign data
   * @param algorithm algorithm used to sign data
   */
  public BackChannelRequestSigner(JWSSigner signer, JWSAlgorithm algorithm) {
    this.signer = signer;
    this.algorithm = algorithm;
  }

  /**
   * Sign payload data
   *
   * @param payload payload to sign in the signed data
   * @return the bytes of the signed JWS
   * @throws JOSEException error signing the payload
   */
  public byte[] signPayload(byte[] payload) throws JOSEException {

    Objects.requireNonNull(payload, "Payload must not be null");
    JWSHeader.Builder builder = new JWSHeader.Builder(algorithm);
    builder.type(JOSEObjectType.JOSE);
    JWSHeader header = builder.build();
    JWSObject jwsObject = new JWSObject(header, new Payload(payload));
    jwsObject.sign(signer);
    if (log.isTraceEnabled()) {
      log.trace("Created signed jws:\n{}", jwsObject.serialize());
    }
    return jwsObject.serialize().getBytes(StandardCharsets.UTF_8);
  }

}
