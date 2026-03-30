package com.jetbrains.signatureverifier.crypt;

import com.jetbrains.signatureverifier.Messages;
import com.jetbrains.signatureverifier.bouncycastle.cms.SignerInformation;
import com.jetbrains.signatureverifier.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

public class SignerInfoVerifier {
  private static final Logger LOG = LoggerFactory.getLogger(SignerInfoVerifier.class);

  private final SignerInformation signer;
  private final Store<X509CertificateHolder> certs;
  private final CrlProvider crlProvider;

  // lazy fields
  private boolean timeStampTokenComputed = false;
  private TimeStampToken timeStampToken;
  private boolean counterSignaturesComputed = false;
  private Collection<SignerInformation> counterSignatures;

  public SignerInfoVerifier(
    SignerInformation signer,
    Store<X509CertificateHolder> certs,
    CrlProvider crlProvider) {
    this.signer = signer;
    this.certs = certs;
    this.crlProvider = crlProvider;
  }

  public VerifySignatureResult verifyAsync(SignatureVerificationParams signatureVerificationParams) throws Exception {
    @SuppressWarnings("unchecked")
    List<X509CertificateHolder> certList =
      new ArrayList<>(certs.getMatches((Selector<X509CertificateHolder>) signer.getSID()));
    if (certList.isEmpty()) {
      LOG.error(Messages.signer_cert_not_found);
      return new VerifySignatureResult(VerifySignatureStatus.InvalidSignature, Messages.signer_cert_not_found);
    }
    X509CertificateHolder cert = certList.get(0);
    try {
      org.bouncycastle.cms.SignerInformationVerifier verifier =
        new JcaSignerInfoVerifierBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(cert);

      if (!signer.verify(verifier))
        return new VerifySignatureResult(VerifySignatureStatus.InvalidSignature);

      if (signatureVerificationParams.buildChain)
        applySignValidationTime(signatureVerificationParams);

      VerifySignatureResult verifyCounterSignResult = verifyCounterSignAsync(signatureVerificationParams);
      if (verifyCounterSignResult.isNotValid()) return verifyCounterSignResult;

      VerifySignatureResult verifyTimeStampResult = verifyTimeStampAsync(signatureVerificationParams);
      if (verifyTimeStampResult.isNotValid()) return verifyTimeStampResult;

      VerifySignatureResult verifyNestedSignsResult = verifyNestedSignsAsync(signatureVerificationParams);
      if (verifyNestedSignsResult.isNotValid()) return verifyNestedSignsResult;

      if (signatureVerificationParams.buildChain)
        return buildCertificateChainAsync(cert, certs, signatureVerificationParams);

      return VerifySignatureResult.Valid;
    } catch (CMSException ex) {
      return new VerifySignatureResult(VerifySignatureStatus.InvalidSignature, Utils.flatMessages(ex));
    } catch (CertificateExpiredException ex) {
      return new VerifySignatureResult(VerifySignatureStatus.InvalidSignature, Utils.flatMessages(ex));
    }
  }

  private void applySignValidationTime(SignatureVerificationParams params) {
    if (params.signValidationTimeMode != SignatureValidationTimeMode.Timestamp
      || params.signatureValidationTime != null)
      return;
    Date signValidationTime = getSigningTime();
    if (signValidationTime == null) signValidationTime = getTimestamp();
    if (signValidationTime != null)
      params.setSignValidationTime(Utils.convertToLocalDateTime(signValidationTime));
    else
      LOG.warn("Unknown sign validation time");
  }

  private VerifySignatureResult verifyNestedSignsAsync(SignatureVerificationParams params) throws Exception {
    VerifySignatureResult r1 = verifyNestedSignsAsync(OIDs.SPC_NESTED_SIGNATURE, params);
    if (r1.isNotValid()) return r1;
    VerifySignatureResult r2 = verifyNestedSignsAsync(OIDs.MS_COUNTER_SIGN, params);
    if (r2.isNotValid()) return r2;
    return VerifySignatureResult.Valid;
  }

  private VerifySignatureResult verifyNestedSignsAsync(ASN1ObjectIdentifier attrOid,
                                                        SignatureVerificationParams params) throws Exception {
    if (signer.getUnsignedAttributes() == null) return VerifySignatureResult.Valid;
    org.bouncycastle.asn1.ASN1EncodableVector nestedSignAttrs = signer.getUnsignedAttributes().getAll(attrOid);
    if (nestedSignAttrs == null || nestedSignAttrs.size() == 0) return VerifySignatureResult.Valid;

    for (int i = 0; i < nestedSignAttrs.size(); i++) {
      Attribute nestedSignAttr = (Attribute) nestedSignAttrs.get(i);
      org.bouncycastle.asn1.ASN1Set attrValues = nestedSignAttr.getAttrValues();
      for (int j = 0; j < attrValues.size(); j++) {
        SignedMessage nestedSignedMessage = new SignedMessage(attrValues.getObjectAt(j).toASN1Primitive());
        VerifySignatureResult result = new SignedMessageVerifier(crlProvider)
          .verifySignatureAsync(nestedSignedMessage, params);
        if (result.isNotValid()) return result;
      }
    }
    return VerifySignatureResult.Valid;
  }

  private VerifySignatureResult verifyCounterSignAsync(SignatureVerificationParams params) throws Exception {
    for (SignerInformation signerInfo : getCounterSignatures()) {
      SignerInfoVerifier siv = new SignerInfoVerifier(signerInfo, certs, crlProvider);
      VerifySignatureResult res = siv.verifyAsync(params);
      if (res.isNotValid()) return res;
    }
    return VerifySignatureResult.Valid;
  }

  private VerifySignatureResult verifyTimeStampAsync(SignatureVerificationParams params) throws Exception {
    TimeStampToken tst = getTimeStampToken();
    if (tst == null) return VerifySignatureResult.Valid;

    Store<X509CertificateHolder> tstCerts = tst.getCertificates();
    @SuppressWarnings("unchecked")
    List<X509CertificateHolder> tstCertsList =
      new ArrayList<>(tstCerts.getMatches((Selector<X509CertificateHolder>) tst.getSID()));
    if (tstCertsList.isEmpty())
      return new VerifySignatureResult(VerifySignatureStatus.InvalidTimestamp, Messages.signer_cert_not_found);

    X509CertificateHolder tstCert = tstCertsList.get(0);
    try {
      org.bouncycastle.cms.SignerInformationVerifier verifier =
        new JcaSignerInfoVerifierBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(tstCert);
      tst.validate(verifier);
      if (params.buildChain) {
        try {
          CMSSignedData tstCmsSignedData = tst.toCMSSignedData();
          Store<X509CertificateHolder> certs = tstCmsSignedData.getCertificates();
          return buildCertificateChainAsync(tstCert, certs, params);
        } catch (CertPathBuilderException ex) {
          return VerifySignatureResult.invalidChain(Utils.flatMessages(ex));
        }
      }
    } catch (TSPException ex) {
      return new VerifySignatureResult(VerifySignatureStatus.InvalidTimestamp, Utils.flatMessages(ex));
    } catch (CertificateExpiredException ex) {
      return new VerifySignatureResult(VerifySignatureStatus.InvalidTimestamp, Utils.flatMessages(ex));
    }
    return VerifySignatureResult.Valid;
  }

  private VerifySignatureResult buildCertificateChainAsync(
    X509CertificateHolder primary,
    Store<X509CertificateHolder> intermediateCertsStore,
    SignatureVerificationParams params) throws Exception {

    LOG.trace("Signature validation time: {}",
      Utils.toString(params.signatureValidationTime, "dd.MM.uuuu HH:mm:ss"));

    CustomPkixBuilderParameters builderParams = new CustomPkixBuilderParameters(
      params.getRootCertificates(),
      intermediateCertsStore,
      new X509CertSelector() {{ setCertificate(BcExt.toJavaX509Certificate(primary)); }},
      params.signatureValidationTime
    );

    boolean useOCSP = params.withRevocationCheck && builderParams.prepareCrls(crlProvider);

    try {
      CertPathBuilder builder = CertPathBuilder.getInstance(CertPathBuilder.getDefaultType());
      PKIXCertPathBuilderResult chain = (PKIXCertPathBuilderResult) builder.build(builderParams);

      if (useOCSP) {
        LOG.trace("Start OCSP for certificate {}", BcExt.formatId(primary));
        X509CertificateHolder issuerCert = getIssuerCert(chain, primary);
        return new OcspVerifier(params.ocspResponseTimeout)
          .checkCertificateRevocationStatusAsync(primary, issuerCert);
      }
      return VerifySignatureResult.Valid;
    } catch (CertPathBuilderException ex) {
      LOG.error("Build chain for certificate was failed. {} {}", BcExt.formatId(primary), Utils.flatMessages(ex));
      return VerifySignatureResult.invalidChain(Utils.flatMessages(ex));
    }
  }

  private X509CertificateHolder getIssuerCert(PKIXCertPathBuilderResult chain, X509CertificateHolder cert)
    throws Exception {
    List<? extends java.security.cert.Certificate> certPathCerts = chain.getCertPath().getCertificates();
    for (int i = certPathCerts.size() - 1; i >= 0; i--) {
      X509CertificateHolder holder = BcExt.toX509CertificateHolder(certPathCerts.get(i));
      if (holder.getSubject().equals(cert.getIssuer())) return holder;
    }
    java.security.cert.X509Certificate trustCert = chain.getTrustAnchor().getTrustedCert();
    return trustCert != null ? BcExt.toX509CertificateHolder(trustCert) : null;
  }

  private Collection<SignerInformation> getCounterSignatures() {
    if (!counterSignaturesComputed) {
      counterSignatures = computeCounterSignatures(signer);
      counterSignaturesComputed = true;
    }
    return counterSignatures;
  }

  private List<SignerInformation> computeCounterSignatures(SignerInformation current) {
    List<SignerInformation> res = new ArrayList<>();
    for (SignerInformation signer : current.getCounterSignatures().getSigners()) {
      res.add(signer);
      res.addAll(computeCounterSignatures(signer));
    }
    return res;
  }

  private TimeStampToken getTimeStampToken() {
    if (!timeStampTokenComputed) {
      timeStampToken = computeTimeStampToken();
      timeStampTokenComputed = true;
    }
    return timeStampToken;
  }

  private TimeStampToken computeTimeStampToken() {
    ASN1Encodable timestampAttrValue = getUnsignedAttributeValue(OIDs.MS_COUNTER_SIGN);
    if (timestampAttrValue == null)
      timestampAttrValue = getUnsignedAttributeValue(OIDs.TIMESTAMP_TOKEN);
    if (timestampAttrValue == null) return null;
    try {
      ContentInfo contentInfo = ContentInfo.getInstance(timestampAttrValue);
      CMSSignedData cmsSignedData = new CMSSignedData(contentInfo);
      return new TimeStampToken(cmsSignedData);
    } catch (Exception e) {
      return null;
    }
  }

  private Date getTimestamp() {
    TimeStampToken tst = getTimeStampToken();
    if (tst != null && tst.timeStampInfo() != null && tst.timeStampInfo().getGenTime() != null)
      return tst.timeStampInfo().getGenTime();
    return getTimeStampFromCounterSign();
  }

  private Date getTimeStampFromCounterSign() {
    for (SignerInformation signer : getCounterSignatures()) {
      if (signer.getSignedAttributes() == null) continue;
      Attribute signingTimeAttribute = signer.getSignedAttributes().get(OIDs.SIGNING_TIME);
      if (signingTimeAttribute != null && signingTimeAttribute.getAttrValues().size() > 0) {
        ASN1Encodable attrValue = signingTimeAttribute.getAttrValues().getObjectAt(0);
        Time time = Time.getInstance(attrValue);
        return time.getDate();
      }
    }
    return null;
  }

  private Date getSigningTime() {
    ASN1Encodable signingTime = getSignedAttributeValue(CMSAttributes.signingTime);
    return signingTime == null ? null : Time.getInstance(signingTime).getDate();
  }

  private ASN1Encodable getSignedAttributeValue(ASN1ObjectIdentifier oid) {
    if (signer.getSignedAttributes() == null) return null;
    return BcExt.getFirstAttributeValue(signer.getSignedAttributes(), oid);
  }

  private ASN1Encodable getUnsignedAttributeValue(ASN1ObjectIdentifier oid) {
    if (signer.getUnsignedAttributes() == null) return null;
    return BcExt.getFirstAttributeValue(signer.getUnsignedAttributes(), oid);
  }
}
