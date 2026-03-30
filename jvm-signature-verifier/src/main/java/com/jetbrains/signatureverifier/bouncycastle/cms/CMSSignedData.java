package com.jetbrains.signatureverifier.bouncycastle.cms;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;

public class CMSSignedData implements Encodable {
  SignedData signedData;
  ContentInfo contentInfo;
  CMSTypedData signedContent;
  SignerInformationStore signerInfoStore;
  private Map<?, ?> hashes;

  private CMSSignedData(CMSSignedData c) {
    signedData = c.signedData;
    contentInfo = c.contentInfo;
    signedContent = c.signedContent;
    signerInfoStore = c.signerInfoStore;
  }

  public CMSSignedData(byte[] sigBlock) throws CMSException {
    this(CMSUtils.readContentInfo(sigBlock));
  }

  public CMSSignedData(CMSProcessable signedContent, byte[] sigBlock) throws CMSException {
    this(signedContent, CMSUtils.readContentInfo(sigBlock));
  }

  public CMSSignedData(Map<?, ?> hashes, byte[] sigBlock) throws CMSException {
    this(hashes, CMSUtils.readContentInfo(sigBlock));
  }

  public CMSSignedData(CMSProcessable signedContent, InputStream sigData) throws CMSException {
    this(signedContent, CMSUtils.readContentInfo(sigData));
  }

  public CMSSignedData(InputStream sigData) throws CMSException {
    this(CMSUtils.readContentInfo(sigData));
  }

  public CMSSignedData(CMSProcessable signedContent, ContentInfo sigData) throws CMSException {
    contentInfo = sigData;
    signedData = getSignedDataX();
    if (signedContent instanceof CMSTypedData) {
      this.signedContent = (CMSTypedData) signedContent;
    } else {
      ASN1ObjectIdentifier contentType = signedData.getEncapContentInfo().getContentType();
      this.signedContent = new CMSTypedData() {
        @Override
        public ASN1ObjectIdentifier getContentType() { return contentType; }
        @Override
        public void write(OutputStream out) throws IOException, CMSException { signedContent.write(out); }
        @Override
        public Object getContent() { return signedContent.getContent(); }
      };
    }
  }

  public CMSSignedData(Map<?, ?> hashes, ContentInfo sigData) throws CMSException {
    this.hashes = hashes;
    contentInfo = sigData;
    signedData = getSignedDataX();
  }

  public CMSSignedData(ContentInfo sigData) throws CMSException {
    contentInfo = sigData;
    signedData = getSignedDataX();

    ASN1Encodable content = signedData.getEncapContentInfo().getContent();
    if (content != null) {
      if (content instanceof ASN1OctetString) {
        this.signedContent = new CMSProcessableByteArray(
          signedData.getEncapContentInfo().getContentType(),
          ((ASN1OctetString) content).getOctets()
        );
      } else {
        this.signedContent = new PKCS7ProcessableObject(
          signedData.getEncapContentInfo().getContentType(), content);
      }
    } else {
      this.signedContent = null;
    }
  }

  private SignedData getSignedDataX() throws CMSException {
    try {
      return SignedData.getInstance(contentInfo.getContent());
    } catch (ClassCastException e) {
      throw new CMSException("Malformed content.", e);
    } catch (IllegalArgumentException e) {
      throw new CMSException("Malformed content.", e);
    }
  }

  public int getVersion() {
    return signedData.getVersion().intValueExact();
  }

  public SignerInformationStore getSignerInfos() {
    if (signerInfoStore == null) {
      ASN1Set s = signedData.getSignerInfos();
      List<SignerInformation> signerInfos = new ArrayList<>();
      for (int i = 0; i < s.size(); i++) {
        SignerInfo si = SignerInfo.getInstance(s.getObjectAt(i));
        ASN1ObjectIdentifier contentType = signedData.getEncapContentInfo().getContentType();
        if (hashes == null) {
          signerInfos.add(new SignerInformation(si, contentType, signedContent, null));
        } else {
          Object firstKey = hashes.keySet().iterator().next();
          byte[] hash = (firstKey instanceof String)
            ? (byte[]) hashes.get(si.getDigestAlgorithm().getAlgorithm().getId())
            : (byte[]) hashes.get(si.getDigestAlgorithm().getAlgorithm());
          signerInfos.add(new SignerInformation(si, contentType, null, hash));
        }
      }
      signerInfoStore = new SignerInformationStore(signerInfos);
    }
    return signerInfoStore;
  }

  // Kotlin-style accessor
  public SignerInformationStore signerInfos() { return getSignerInfos(); }

  public boolean isDetachedSignature() {
    return signedData.getEncapContentInfo().getContent() == null && signedData.getSignerInfos().size() > 0;
  }

  public boolean isCertificateManagementMessage() {
    return signedData.getEncapContentInfo().getContent() == null && signedData.getSignerInfos().size() == 0;
  }

  public Store<X509CertificateHolder> getCertificates() {
    return HELPER.getCertificates(signedData.getCertificates());
  }

  // Kotlin-style accessor
  public Store<X509CertificateHolder> certificates() { return getCertificates(); }

  public Store<X509CRLHolder> getCRLs() {
    return HELPER.getCRLs(signedData.getCRLs());
  }

  public Store<X509AttributeCertificateHolder> getAttributeCertificates() {
    return HELPER.getAttributeCertificates(signedData.getCertificates());
  }

  public Store<?> getOtherRevocationInfo(ASN1ObjectIdentifier otherRevocationInfoFormat) {
    return HELPER.getOtherRevocationInfo(otherRevocationInfoFormat, signedData.getCRLs());
  }

  public Set<AlgorithmIdentifier> getDigestAlgorithmIDs() {
    Set<AlgorithmIdentifier> digests = new HashSet<>(signedData.getDigestAlgorithms().size());
    Enumeration<?> en = signedData.getDigestAlgorithms().getObjects();
    while (en.hasMoreElements()) {
      digests.add(AlgorithmIdentifier.getInstance(en.nextElement()));
    }
    return Collections.unmodifiableSet(digests);
  }

  public CMSTypedData getSignedContent() {
    return signedContent;
  }

  public String getSignedContentTypeOID() {
    return signedData.getEncapContentInfo().getContentType().getId();
  }

  // Kotlin-style accessor
  public String signedContentTypeOID() { return getSignedContentTypeOID(); }

  public ContentInfo toASN1Structure() {
    return contentInfo;
  }

  @Override
  public byte[] getEncoded() throws IOException {
    return contentInfo.getEncoded();
  }

  public byte[] getEncoded(String encoding) throws IOException {
    return contentInfo.getEncoded(encoding);
  }

  public boolean verifySignatures(SignerInformationVerifierProvider verifierProvider) throws CMSException {
    return verifySignatures(verifierProvider, false);
  }

  public boolean verifySignatures(SignerInformationVerifierProvider verifierProvider,
                                   boolean ignoreCounterSignatures) throws CMSException {
    for (SignerInformation signer : signerInfoStore != null ? signerInfoStore.getSigners() : getSignerInfos().getSigners()) {
      try {
        SignerInformationVerifier verifier = verifierProvider.get(signer.getSID());
        if (!signer.verify(verifier)) return false;
        if (!ignoreCounterSignatures) {
          for (SignerInformation counterSigner : signer.getCounterSignatures().getSigners()) {
            if (!verifyCounterSignature(counterSigner, verifierProvider)) return false;
          }
        }
      } catch (OperatorCreationException e) {
        throw new CMSException("failure in verifier provider: " + e.getMessage(), e);
      }
    }
    return true;
  }

  private boolean verifyCounterSignature(SignerInformation counterSigner,
                                          SignerInformationVerifierProvider verifierProvider)
    throws OperatorCreationException, CMSException {
    SignerInformationVerifier counterVerifier = verifierProvider.get(counterSigner.getSID());
    if (!counterSigner.verify(counterVerifier)) return false;
    for (SignerInformation nested : counterSigner.getCounterSignatures().getSigners()) {
      if (!verifyCounterSignature(nested, verifierProvider)) return false;
    }
    return true;
  }

  private static final CMSSignedHelper HELPER = CMSSignedHelper.INSTANCE;
  private static final DefaultDigestAlgorithmIdentifierFinder dgstAlgFinder =
    new DefaultDigestAlgorithmIdentifierFinder();

  public static CMSSignedData addDigestAlgorithm(CMSSignedData signedData, AlgorithmIdentifier digestAlgorithm) {
    Set<AlgorithmIdentifier> digestAlgorithms = signedData.getDigestAlgorithmIDs();
    AlgorithmIdentifier digestAlg = CMSSignedHelper.INSTANCE.fixDigestAlgID(digestAlgorithm, dgstAlgFinder);
    if (digestAlgorithms.contains(digestAlg)) return signedData;

    CMSSignedData cms = new CMSSignedData(signedData);
    Set<AlgorithmIdentifier> digestAlgs = new HashSet<>();
    for (AlgorithmIdentifier alg : digestAlgorithms) {
      digestAlgs.add(CMSSignedHelper.INSTANCE.fixDigestAlgID(alg, dgstAlgFinder));
    }
    digestAlgs.add(digestAlg);

    ASN1Set digests = CMSUtils.convertToBERSet(digestAlgs);
    ASN1Sequence sD = (ASN1Sequence) signedData.signedData.toASN1Primitive();
    ASN1EncodableVector vec = new ASN1EncodableVector();
    vec.add(sD.getObjectAt(0)); // version
    vec.add(digests);
    for (int i = 2; i < sD.size(); i++) vec.add(sD.getObjectAt(i));
    cms.signedData = SignedData.getInstance(new BERSequence(vec));
    cms.contentInfo = new ContentInfo(cms.contentInfo.getContentType(), cms.signedData);
    return cms;
  }

  public static CMSSignedData replaceSigners(CMSSignedData signedData, SignerInformationStore signerInformationStore) {
    CMSSignedData cms = new CMSSignedData(signedData);
    cms.signerInfoStore = signerInformationStore;

    Set<AlgorithmIdentifier> digestAlgs = new HashSet<>();
    ASN1EncodableVector vec = new ASN1EncodableVector();
    for (SignerInformation signer : signerInformationStore.getSigners()) {
      CMSUtils.addDigestAlgs(digestAlgs, signer, dgstAlgFinder);
      vec.add(signer.toASN1Structure());
    }

    ASN1Set digests = CMSUtils.convertToBERSet(digestAlgs);
    ASN1Set signers = new DLSet(vec);
    ASN1Sequence sD = (ASN1Sequence) signedData.signedData.toASN1Primitive();
    ASN1EncodableVector vec2 = new ASN1EncodableVector();
    vec2.add(sD.getObjectAt(0)); // version
    vec2.add(digests);
    for (int i = 2; i < sD.size() - 1; i++) vec2.add(sD.getObjectAt(i));
    vec2.add(signers);
    cms.signedData = SignedData.getInstance(new BERSequence(vec2));
    cms.contentInfo = new ContentInfo(cms.contentInfo.getContentType(), cms.signedData);
    return cms;
  }

  public static CMSSignedData replaceCertificatesAndCRLs(
    CMSSignedData signedData,
    Store<X509CertificateHolder> certificates,
    Store<X509AttributeCertificateHolder> attrCerts,
    Store<X509CRLHolder> revocations) throws CMSException {

    CMSSignedData cms = new CMSSignedData(signedData);
    ASN1Set certSet = null;
    ASN1Set crlSet = null;

    if (certificates != null || attrCerts != null) {
      List<Object> certs = new ArrayList<>();
      if (certificates != null) certs.addAll(CMSUtils.getCertificatesFromStore(certificates));
      if (attrCerts != null) certs.addAll(CMSUtils.getAttributeCertificatesFromStore(attrCerts));
      ASN1Set set = CMSUtils.createBerSetFromList(certs);
      if (set.size() != 0) certSet = set;
    }
    if (revocations != null) {
      ASN1Set set = CMSUtils.createBerSetFromList(CMSUtils.getCRLsFromStore(revocations));
      if (set.size() != 0) crlSet = set;
    }

    cms.signedData = new SignedData(
      signedData.signedData.getDigestAlgorithms(),
      signedData.signedData.getEncapContentInfo(),
      certSet, crlSet,
      signedData.signedData.getSignerInfos()
    );
    cms.contentInfo = new ContentInfo(cms.contentInfo.getContentType(), cms.signedData);
    return cms;
  }
}
