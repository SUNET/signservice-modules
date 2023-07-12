package se.sunet.edusign.harica.authn.service;

import org.apache.http.StatusLine;

import lombok.Getter;

/**
 * HttpResponseData
 */
@Getter
public class HttpResponseData{

  public HttpResponseData(StatusLine statusLine, byte[] data) {
    this.statusLine = statusLine;
    this.data = data;
  }

  private StatusLine statusLine;
  private byte[] data;

}
