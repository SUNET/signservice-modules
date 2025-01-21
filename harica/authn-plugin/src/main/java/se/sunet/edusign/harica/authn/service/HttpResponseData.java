package se.sunet.edusign.harica.authn.service;


import lombok.Getter;
import org.apache.hc.core5.http.message.StatusLine;

/**
 * HttpResponseData
 */
@Getter
public class HttpResponseData {

  public HttpResponseData(StatusLine statusLine, byte[] data) {
    this.statusLine = statusLine;
    this.data = data;
  }

  private StatusLine statusLine;
  private byte[] data;

}
