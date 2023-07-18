package se.sunet.edusign.harica.authn.service;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;

import lombok.RequiredArgsConstructor;

/**
 * Connector for sending backend requests to the CA service
 */
@RequiredArgsConstructor
public class CARequestConnector {

  private final CloseableHttpClient httpClient;
  private final int connectTimeout;
  private final int readTimeout;

  public String getStringResponse(HttpResponseData httpResponseData) throws IOException {
    return new String(httpResponseData.getData());
  }

  public HttpResponseData postRequest(String url, byte[] payload) throws IOException {
    HttpPost request = new HttpPost(url);
    request.setConfig(RequestConfig.custom()
      .setConnectTimeout(connectTimeout)
      .setConnectionRequestTimeout(connectTimeout)
      .setSocketTimeout(readTimeout)
      .build());

    //request.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
    request.setHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType());
    request.setEntity(new ByteArrayEntity(payload));
    CloseableHttpResponse response = httpClient.execute(request);
    byte[] data = IOUtils.toByteArray(response.getEntity().getContent());
    response.close();
    return new HttpResponseData(response.getStatusLine(), data);
  }

}
