package se.sunet.edusign.harica.authn.service.dto;

import java.math.BigInteger;
import java.util.Random;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

@Data
public class CaCertificateRequest {

  public CaCertificateRequest(String signatureId, String uniqueIdentifier, String csr, String returnURL) {
    this.signatureId = signatureId;
    this.uniqueIdentifier = uniqueIdentifier;
    this.csr = csr;
    this.transactionType = "ADVANCED_IV_NATURAL";
    this.returnURL = returnURL;
  }

  public CaCertificateRequest(String uniqueIdentifier, String csr, String returnURL) {
    this("id_" + new BigInteger(128, new Random()).toString(16), uniqueIdentifier,csr,returnURL);
  }

  private String signatureId;
  private String transactionType;
  @JsonProperty("CSR")
  private String csr;
  private String uniqueIdentifier;
  private String returnURL;

}
