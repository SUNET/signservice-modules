package se.sunet.edusign.harica.authn.service.token;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;

import lombok.RequiredArgsConstructor;

/**
 * Description
 */
@RequiredArgsConstructor
public class ResponseParser {

  private final ObjectMapper objectMapper;
  private final CertificateFactory certificateFactory;

  public CaCertificateResponse parseTokenPayload(Payload payload) throws IOException, CertificateException {

    CaCertificateResponse.CaCertificateResponseBuilder builder = CaCertificateResponse.builder();

    Map responsemap = objectMapper.readValue(payload.toString(),
      Map.class);

    try(PEMParser pemParser = new PEMParser(new StringReader((String)responsemap.get("certificate")))) {
      //PemObject pemObject = pemParser.readPemObject();
      Object certObject = pemParser.readObject();
      if (certObject instanceof X509CertificateHolder) {
        builder.certificate(getCert(certObject));
      }
    }
    try(PEMParser pemParser = new PEMParser(new StringReader((String)responsemap.get("certificate")))) {

      List<X509Certificate> certChain = new ArrayList<>();
      for (Object pkcs7Object = pemParser.readObject(); pkcs7Object != null; pkcs7Object = pemParser.readObject()) {
        if (pkcs7Object instanceof X509CertificateHolder) {
          certChain.add(getCert(pkcs7Object));
        }
      }
      builder.chain(certChain);
    }
    return builder
      .signatureId((String) responsemap.get("signatureId"))
      .uniqueIdentifier((String) responsemap.get("uniqueIdentifier"))
      .build();
  }

  private X509Certificate getCert(Object certHolderObj) throws CertificateException {
    try{
      return (X509Certificate) certificateFactory.generateCertificate(
        new ByteArrayInputStream(((X509CertificateHolder) certHolderObj).getEncoded()));
    } catch (IOException ex) {
      throw new CertificateException("Unable to parse certificate holder object");
    }
  }

}
