package se.sunet.edusign.harica.authn.service;


import lombok.Getter;
import org.apache.hc.core5.http.message.StatusLine;

/**
 * HttpResponseData
 */
@Getter
public class HttpResponseData {

  public HttpResponseData(int responseCode, byte[] data) {
    this.responseCode = responseCode;
    this.data = data;
  }

  private int responseCode;
  private byte[] data;

}
