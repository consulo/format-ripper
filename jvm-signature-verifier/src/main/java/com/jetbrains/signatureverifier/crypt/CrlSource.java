package com.jetbrains.signatureverifier.crypt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class CrlSource {
  private static final Logger LOG = LoggerFactory.getLogger(CrlSource.class);

  public byte[] GetCrlAsync(String url) throws Exception {
    try {
      HttpClient httpClient = HttpClient.newHttpClient();
      HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).GET().build();
      HttpResponse<byte[]> response = httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofByteArray()).join();

      if (response.statusCode() != 200) {
        LOG.warn("CRL downloading fail from {} Status: {}", url, response.statusCode());
        return null;
      }
      return response.body();
    } catch (Exception ex) {
      throw new Exception("Cannot download CRL from: " + url, ex);
    }
  }
}
