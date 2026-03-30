package com.jetbrains.signatureverifier.crypt;

import com.jetbrains.signatureverifier.ILogger;
import com.jetbrains.signatureverifier.NullLogger;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class CrlSource {
  private final ILogger _logger;

  public CrlSource() {
    this(NullLogger.Instance);
  }

  public CrlSource(ILogger logger) {
    _logger = logger != null ? logger : NullLogger.Instance;
  }

  public byte[] GetCrlAsync(String url) throws Exception {
    try {
      HttpClient httpClient = HttpClient.newHttpClient();
      HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).GET().build();
      HttpResponse<byte[]> response = httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofByteArray()).join();

      if (response.statusCode() != 200) {
        _logger.Warning("CRL downloading fail from " + url + " Status: " + response.statusCode());
        return null;
      }
      return response.body();
    } catch (Exception ex) {
      throw new Exception("Cannot download CRL from: " + url, ex);
    }
  }
}
