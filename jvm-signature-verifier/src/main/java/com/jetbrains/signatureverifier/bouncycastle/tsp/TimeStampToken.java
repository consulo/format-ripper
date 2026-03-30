package com.jetbrains.signatureverifier.bouncycastle.tsp;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collection;

/**
 * Carrier class for a TimeStampToken.
 */
public class TimeStampToken {
  CMSSignedData tsToken;
  final SignerInformation tsaSignerInfo;
  final TimeStampTokenInfo timeStampInfo;
  private final CertID certID;

  public TimeStampToken(ContentInfo contentInfo) throws TSPException {
    this(getSignedData(contentInfo));
  }

  public TimeStampToken(CMSSignedData tsToken) throws TSPException {
    this.tsToken = tsToken;
    if (!tsToken.getSignedContentTypeOID().equals(PKCSObjectIdentifiers.id_ct_TSTInfo.getId())) {
      throw new TSPValidationException("ContentInfo object not for a time stamp.");
    }

    Collection<SignerInformation> signers = tsToken.getSignerInfos().getSigners();
    if (signers.size() != 1) {
      throw new IllegalArgumentException("Time-stamp token signed by " + signers.size()
        + " signers, but it must contain just the TSA signature.");
    }
    tsaSignerInfo = signers.iterator().next();

    try {
      CMSProcessable content = tsToken.getSignedContent();
      ByteArrayOutputStream bOut = new ByteArrayOutputStream();
      content.write(bOut);
      timeStampInfo = new TimeStampTokenInfo(
        TSTInfo.getInstance(ASN1Primitive.fromByteArray(bOut.toByteArray())));

      AttributeTable signedAttrs = tsaSignerInfo.getSignedAttributes();
      org.bouncycastle.asn1.cms.Attribute attr = signedAttrs.get(PKCSObjectIdentifiers.id_aa_signingCertificate);
      if (attr != null) {
        SigningCertificate signCert = SigningCertificate.getInstance(attr.getAttrValues().getObjectAt(0));
        certID = new CertID(ESSCertID.getInstance(signCert.getCerts()[0]));
      } else {
        attr = signedAttrs.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
        if (attr == null) {
          throw new TSPValidationException("no signing certificate attribute found, time stamp invalid.");
        }
        SigningCertificateV2 signCertV2 = SigningCertificateV2.getInstance(attr.getAttrValues().getObjectAt(0));
        certID = new CertID(ESSCertIDv2.getInstance(signCertV2.getCerts()[0]));
      }
    } catch (CMSException e) {
      throw new TSPException(e.getMessage(), e.getUnderlyingException());
    } catch (IOException e) {
      throw new TSPException("problem processing content: " + e, e);
    }
  }

  public SignerId getSID() { return tsaSignerInfo.getSID(); }
  public AttributeTable getSignedAttributes() { return tsaSignerInfo.getSignedAttributes(); }
  public AttributeTable getUnsignedAttributes() { return tsaSignerInfo.getUnsignedAttributes(); }
  public Store<X509CertificateHolder> getCertificates() { return tsToken.getCertificates(); }
  public Store<X509CRLHolder> getCRLs() { return tsToken.getCRLs(); }
  public Store<X509AttributeCertificateHolder> getAttributeCertificates() { return tsToken.getAttributeCertificates(); }

  // Kotlin-style accessors
  public Store<X509CertificateHolder> certificates() { return getCertificates(); }
  public TimeStampTokenInfo timeStampInfo() { return timeStampInfo; }
  public SignerId sID() { return getSID(); }

  public void validate(SignerInformationVerifier sigVerifier) throws TSPException, TSPValidationException {
    if (!sigVerifier.hasAssociatedCertificate())
      throw new IllegalArgumentException("verifier provider needs an associated certificate");
    try {
      X509CertificateHolder certHolder = sigVerifier.getAssociatedCertificate();
      org.bouncycastle.operator.DigestCalculator calc = sigVerifier.getDigestCalculator(certID.getHashAlgorithm());
      java.io.OutputStream cOut = calc.getOutputStream();
      cOut.write(certHolder.getEncoded());
      cOut.close();

      if (!Arrays.constantTimeAreEqual(certID.getCertHash(), calc.getDigest())) {
        throw new TSPValidationException("certificate hash does not match certID hash.");
      }
      if (certID.getIssuerSerial() != null) {
        IssuerAndSerialNumber issuerSerial = new IssuerAndSerialNumber(certHolder.toASN1Structure());
        if (!certID.getIssuerSerial().getSerial().equals(issuerSerial.getSerialNumber())) {
          throw new TSPValidationException("certificate serial number does not match certID for signature.");
        }
        GeneralName[] names = certID.getIssuerSerial().getIssuer().getNames();
        boolean found = false;
        for (GeneralName name : names) {
          if (name.getTagNo() == 4
            && X500Name.getInstance(name.getName()).equals(X500Name.getInstance(issuerSerial.getName()))) {
            found = true;
            break;
          }
        }
        if (!found) {
          throw new TSPValidationException("certificate name does not match certID for signature. ");
        }
      }
      TSPUtil.validateCertificate(certHolder);
      if (!certHolder.isValidOn(timeStampInfo.getGenTime())) {
        throw new TSPValidationException("certificate not valid when time stamp created.");
      }
      if (!tsaSignerInfo.verify(sigVerifier)) {
        throw new TSPValidationException("signature not created by certificate.");
      }
    } catch (CMSException e) {
      if (e.getUnderlyingException() != null) {
        throw new TSPException(e.getMessage(), e.getUnderlyingException());
      } else {
        throw new TSPException("CMS exception: " + e, e);
      }
    } catch (IOException e) {
      throw new TSPException("problem processing certificate: " + e, e);
    } catch (OperatorCreationException e) {
      throw new TSPException("unable to create digest: " + e.getMessage(), e);
    }
  }

  public boolean isSignatureValid(SignerInformationVerifier sigVerifier) throws TSPException {
    try {
      return tsaSignerInfo.verify(sigVerifier);
    } catch (CMSException e) {
      if (e.getUnderlyingException() != null) {
        throw new TSPException(e.getMessage(), e.getUnderlyingException());
      } else {
        throw new TSPException("CMS exception: " + e, e);
      }
    }
  }

  public CMSSignedData toCMSSignedData() {
    return tsToken;
  }

  public byte[] getEncoded() throws IOException {
    return tsToken.getEncoded(ASN1Encoding.DL);
  }

  public byte[] getEncoded(String encoding) throws IOException {
    return tsToken.getEncoded(encoding);
  }

  private static CMSSignedData getSignedData(ContentInfo contentInfo) throws TSPException {
    try {
      return new CMSSignedData(contentInfo);
    } catch (CMSException e) {
      throw new TSPException("TSP parsing error: " + e.getMessage(), e.getCause());
    }
  }

  public class CertID {
    private ESSCertID certID;
    private ESSCertIDv2 certIDv2;

    CertID(ESSCertID certID) {
      this.certID = certID;
      this.certIDv2 = null;
    }

    CertID(ESSCertIDv2 certIDv2) {
      this.certIDv2 = certIDv2;
      this.certID = null;
    }

    public AlgorithmIdentifier getHashAlgorithm() {
      return certID != null
        ? new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)
        : certIDv2.getHashAlgorithm();
    }

    public byte[] getCertHash() {
      return certID != null ? certID.getCertHash() : certIDv2.getCertHash();
    }

    public IssuerSerial getIssuerSerial() {
      return certID != null ? certID.getIssuerSerial() : certIDv2.getIssuerSerial();
    }
  }
}
