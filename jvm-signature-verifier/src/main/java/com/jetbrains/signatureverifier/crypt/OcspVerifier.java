package com.jetbrains.signatureverifier.crypt;

import com.jetbrains.signatureverifier.Messages;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Arrays;

public class OcspVerifier {
  private static final Logger LOG = LoggerFactory.getLogger(OcspVerifier.class);

  private static final String OCSP_REQUEST_TYPE = "application/ocsp-request";
  private static final String OCSP_RESPONSE_TYPE = "application/ocsp-response";

  private Duration ocspResponseTimeout = Duration.ZERO;
  private final Duration ocspResponseCorrectSpan = Duration.ofMinutes(1);

  public OcspVerifier(Duration ocspResponseTimeout) {
    this.ocspResponseTimeout = ocspResponseTimeout;
  }

  public VerifySignatureResult checkCertificateRevocationStatusAsync(
    X509CertificateHolder targetCert,
    X509CertificateHolder issuerCert) throws Exception {

    String ocspUrl = BcExt.getOcspUrl(targetCert);
    if (ocspUrl == null) {
      LOG.warn("The OCSP access data is empty in certificate {}", BcExt.formatId(targetCert));
      LOG.error(Messages.unable_determin_certificate_revocation_status);
      return VerifySignatureResult.invalidChain(Messages.unable_determin_certificate_revocation_status);
    }

    OCSPReqBuilder ocspReqGenerator = new OCSPReqBuilder();
    org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder digestProviderBuilder =
      new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder();
    org.bouncycastle.operator.DigestCalculatorProvider digestCalculatorProvider = digestProviderBuilder.build();
    org.bouncycastle.operator.DigestCalculator digestCalculator =
      digestCalculatorProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
    CertificateID certificateIdReq = new CertificateID(digestCalculator, issuerCert, targetCert.getSerialNumber());
    ocspReqGenerator.addRequest(certificateIdReq);
    OCSPReq ocspReq = ocspReqGenerator.build();
    OCSPResp ocspRes = getOcspResponseAsync(ocspUrl, ocspReq, ocspResponseTimeout);

    if (ocspRes == null || ocspRes.getStatus() != OCSPResp.SUCCESSFUL) {
      LOG.error("OCSP response status: {}", ocspRes != null ? ocspRes.getStatus() : "null");
      return VerifySignatureResult.invalidChain(Messages.unable_determin_certificate_revocation_status);
    }

    BasicOCSPResp basicOcspResp = (BasicOCSPResp) ocspRes.getResponseObject();
    if (basicOcspResp == null) {
      LOG.error("Unknown OCSP response type");
      return VerifySignatureResult.invalidChain(Messages.unable_determin_certificate_revocation_status);
    }

    if (!validateOcspResponse(basicOcspResp))
      return VerifySignatureResult.invalidChain(Messages.invalid_ocsp_response);

    SingleResp[] allResponses = basicOcspResp.getResponses();
    java.util.List<SingleResp> singleResponses = new java.util.ArrayList<>();
    for (SingleResp resp : allResponses) {
      if (resp.getCertID().equals(certificateIdReq))
        singleResponses.add(resp);
    }

    if (singleResponses.isEmpty()) {
      LOG.error("OCSP response not correspond to request");
      return VerifySignatureResult.invalidChain(Messages.invalid_ocsp_response);
    }

    for (SingleResp singleResp : singleResponses) {
      if (!validateSingleOcspResponse(singleResp))
        return VerifySignatureResult.invalidChain(Messages.invalid_ocsp_response);

      Object certStatus = singleResp.getCertStatus();
      if (certStatus == null) {
        continue;
      } else if (certStatus instanceof UnknownStatus) {
        LOG.warn(Messages.unknown_certificate_revocation_status);
        return VerifySignatureResult.invalidChain(Messages.unknown_certificate_revocation_status);
      } else if (certStatus instanceof RevokedStatus) {
        RevokedStatus certRevStatus = (RevokedStatus) certStatus;
        String msg = formatRevokedStatus(certRevStatus);
        LOG.warn(msg);
        return VerifySignatureResult.invalidChain(msg);
      }
    }
    return VerifySignatureResult.Valid;
  }

  private static String formatRevokedStatus(RevokedStatus revokedStatus) {
    String reason = "CrlReason: <none>";
    if (revokedStatus.hasRevocationReason()) {
      CRLReason crlReason = CRLReason.getInstance(new ASN1Enumerated(revokedStatus.getRevocationReason()));
      reason = crlReason.toString();
    }
    return String.format(Messages.certificate_revoked, revokedStatus.getRevocationTime(), reason);
  }

  private OCSPResp getOcspResponseAsync(String ocspResponderUrl, OCSPReq ocspRequest, Duration timeout) throws Exception {
    if (!ocspResponderUrl.startsWith("http")) {
      LOG.error("Only http(s) is supported for OCSP calls");
      return null;
    }
    LOG.trace("OCSP request: {}", ocspResponderUrl);
    try {
      byte[] array = ocspRequest.getEncoded();
      HttpClient httpClient = HttpClient.newBuilder().connectTimeout(timeout).build();
      HttpRequest request = HttpRequest.newBuilder()
        .header("Content-Type", OCSP_REQUEST_TYPE)
        .header("Accept", OCSP_RESPONSE_TYPE)
        .uri(URI.create(ocspResponderUrl))
        .POST(HttpRequest.BodyPublishers.ofByteArray(array))
        .build();

      byte[] responseData = httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofByteArray()).join().body();
      return new OCSPResp(responseData);
    } catch (Exception ex) {
      String msg = "Cannot get OCSP response for url: " + ocspResponderUrl;
      LOG.error(msg);
      throw new Exception(msg, ex);
    }
  }

  private boolean validateOcspResponse(BasicOCSPResp ocspResp) throws Exception {
    X509CertificateHolder issuerCert = getOcspIssuerCert(ocspResp);
    if (issuerCert == null) {
      LOG.error("OCSP issuer certificate not found in response");
      return false;
    }
    if (!BcExt.canSignOcspResponses(issuerCert)) {
      LOG.error("OCSP issuer certificate is not applicable. RFC 6960 3.2");
      return false;
    }
    if (!issuerCert.isValidOn(Utils.convertToDate(nowUtc()))) {
      LOG.error("OCSP issuer certificate is not valid now. RFC 6960 3.2");
      return false;
    }

    JcaContentVerifierProviderBuilder verifierBuilder = new JcaContentVerifierProviderBuilder();
    if (!ocspResp.isSignatureValid(verifierBuilder.build(issuerCert))) {
      LOG.error("OCSP with invalid signature! RFC 6960 3.2");
      return false;
    }
    return true;
  }

  private boolean validateSingleOcspResponse(SingleResp singleResp) {
    LocalDateTime nowInGmt = nowUtc();
    if (singleResp.getNextUpdate() != null
      && singleResp.getNextUpdate().before(Utils.convertToDate(nowInGmt))) {
      LOG.error("OCSP response is no longer valid. RFC 6960 4.2.2.1.");
      return false;
    }
    Duration diff = Duration.between(
      Utils.convertToLocalDateTime(singleResp.getThisUpdate()),
      nowInGmt
    ).abs();
    if (diff.compareTo(ocspResponseCorrectSpan) > 0) {
      LOG.error("OCSP response signature is from the future. Timestamp of thisUpdate field: {}. RFC 6960 4.2.2.1.",
        singleResp.getThisUpdate());
      return false;
    }
    return true;
  }

  private LocalDateTime nowUtc() {
    return LocalDateTime.now(Clock.systemUTC());
  }

  private X509CertificateHolder getOcspIssuerCert(BasicOCSPResp ocspResp) {
    X509CertificateHolder[] certs = ocspResp.getCerts();
    if (certs == null || certs.length < 1) return null;

    org.bouncycastle.cert.ocsp.RespID responderId = ocspResp.getResponderId();
    org.bouncycastle.asn1.ocsp.ResponderID responderIdObj = responderId.toASN1Primitive();

    if (responderIdObj.getName() != null) {
      for (X509CertificateHolder cert : certs) {
        if (cert.getSubject().equals(responderIdObj.getName()))
          return cert;
      }
      return null;
    } else {
      byte[] keyHash = responderIdObj.getKeyHash();
      if (keyHash == null) return null;
      for (X509CertificateHolder cert : certs) {
        byte[] ki = BcExt.getSubjectKeyIdentifierRaw(cert);
        if (ki != null && Arrays.equals(keyHash, ki))
          return cert;
      }
      return null;
    }
  }
}
