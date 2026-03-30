package com.jetbrains.signatureverifier.crypt;

import com.jetbrains.signatureverifier.ILogger;
import com.jetbrains.signatureverifier.NullLogger;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

public class CrlProvider {
  private final CrlSource _crlSource;
  private final CrlCacheFileSystem _crlCash;
  private final ILogger _logger;

  public CrlProvider(ILogger logger) {
    this(new CrlSource(logger), new CrlCacheFileSystem(), logger);
  }

  public CrlProvider(CrlSource crlSource, CrlCacheFileSystem crlCash, ILogger logger) {
    _crlSource = crlSource;
    _crlCash = crlCash;
    _logger = logger != null ? logger : NullLogger.Instance;
  }

  public Collection<X509CRLHolder> GetCrlsAsync(X509CertificateHolder cert) throws Exception {
    String crlId;
    try {
      crlId = BcExt.GetAuthorityKeyIdentifier(cert);
      if (crlId == null) crlId = BcExt.Thumbprint(cert);
    } catch (Exception e) {
      crlId = BcExt.Thumbprint(cert);
    }

    Collection<X509CRLHolder> res = _crlCash.GetCrls(crlId);
    if (!res.isEmpty() && !crlsIsOutDate(res))
      return res;

    List<String> urls = BcExt.GetCrlDistributionUrls(cert);
    if (urls.isEmpty())
      _logger.Warning("No CRL distribution urls in certificate " + BcExt.FormatId(cert));

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

    _crlCash.UpdateCrls(crlId, crlDataList);
    return crls;
  }

  private Collection<byte[]> downloadCrlsAsync(Collection<String> urls) throws Exception {
    List<byte[]> res = new ArrayList<>();
    for (String url : urls) {
      byte[] crlData = _crlSource.GetCrlAsync(url);
      if (crlData != null)
        res.add(crlData);
    }
    return res;
  }

  private boolean crlsIsOutDate(Collection<X509CRLHolder> crls) {
    Date now = Utils.ConvertToDate(LocalDateTime.now());
    for (X509CRLHolder crl : crls) {
      if (crl.getNextUpdate() != null && crl.getNextUpdate().before(now))
        return true;
    }
    return false;
  }
}
