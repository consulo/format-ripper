package com.jetbrains.signatureverifier.crypt;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

public class CrlProvider {
  private static final Logger LOG = LoggerFactory.getLogger(CrlProvider.class);

  private final CrlSource crlSource;
  private final CrlCacheFileSystem crlCash;

  public CrlProvider() {
    this(new CrlSource(), new CrlCacheFileSystem());
  }

  public CrlProvider(CrlSource crlSource, CrlCacheFileSystem crlCash) {
    this.crlSource = crlSource;
    this.crlCash = crlCash;
  }

  public Collection<X509CRLHolder> getCrlsAsync(X509CertificateHolder cert) throws Exception {
    String crlId;
    try {
      crlId = BcExt.getAuthorityKeyIdentifier(cert);
      if (crlId == null) crlId = BcExt.thumbprint(cert);
    } catch (Exception e) {
      crlId = BcExt.thumbprint(cert);
    }

    Collection<X509CRLHolder> res = crlCash.getCrls(crlId);
    if (!res.isEmpty() && !crlsIsOutDate(res))
      return res;

    List<String> urls = BcExt.getCrlDistributionUrls(cert);
    if (urls.isEmpty())
      LOG.warn("No CRL distribution urls in certificate {}", BcExt.formatId(cert));

    Collection<byte[]> crlsData = downloadCrlsAsync(urls);

    List<X509CRLHolder> crls = new ArrayList<>();
    List<byte[]> crlDataList = new ArrayList<>();
    for (byte[] data : crlsData) {
      X509CRLHolder crl = new X509CRLHolder(data);
      if (crl.getNextUpdate() != null) {
        crls.add(crl);
        crlDataList.add(data);
      }
    }

    crlCash.updateCrls(crlId, crlDataList);
    return crls;
  }

  private Collection<byte[]> downloadCrlsAsync(Collection<String> urls) throws Exception {
    List<byte[]> res = new ArrayList<>();
    for (String url : urls) {
      byte[] crlData = crlSource.getCrlAsync(url);
      if (crlData != null)
        res.add(crlData);
    }
    return res;
  }

  private boolean crlsIsOutDate(Collection<X509CRLHolder> crls) {
    Date now = Utils.convertToDate(LocalDateTime.now());
    for (X509CRLHolder crl : crls) {
      if (crl.getNextUpdate() != null && crl.getNextUpdate().before(now))
        return true;
    }
    return false;
  }
}
