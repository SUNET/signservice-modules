package se.sunet.edusign.harica.authn.service;

import lombok.RequiredArgsConstructor;
import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.util.Timeout;

import java.io.IOException;

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
