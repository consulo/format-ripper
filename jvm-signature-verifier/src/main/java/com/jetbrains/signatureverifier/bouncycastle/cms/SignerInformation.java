package com.jetbrains.signatureverifier.bouncycastle.cms;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAlgorithmProtection;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.*;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RawContentVerifier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.TeeOutputStream;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class SignerInformation {
  private final SignerId sID;
  private CMSProcessable content;
  private byte[] signature;
  private final ASN1ObjectIdentifier contentType;
  private final boolean isCounterSignature;

  private AttributeTable signedAttributeValues;
  private AttributeTable unsignedAttributeValues;
  private byte[] resultDigest;
  protected final SignerInfo info;
  private final AlgorithmIdentifier digestAlgorithmID;
  protected AlgorithmIdentifier encryptionAlgorithm;
  protected ASN1Set signedAttributeSet;
  protected ASN1Set unsignedAttributeSet;

  SignerInformation(SignerInfo info, ASN1ObjectIdentifier contentType,
                    CMSProcessable content, byte[] resultDigest) {
    this.info = info;
    this.contentType = contentType;
    this.isCounterSignature = contentType == null;
    ASN1Encodable s = info.getSID().getId();
    if (info.getSID().isTagged()) {
      ASN1OctetString octs = ASN1OctetString.getInstance(s);
      sID = new SignerId(octs.getOctets());
    } else {
      IssuerAndSerialNumber iAnds = IssuerAndSerialNumber.getInstance(s);
      sID = new SignerId(iAnds.getName(), iAnds.getSerialNumber().getValue());
    }
    digestAlgorithmID = info.getDigestAlgorithm();
    signedAttributeSet = info.getAuthenticatedAttributes();
    unsignedAttributeSet = info.getUnauthenticatedAttributes();
    encryptionAlgorithm = info.getDigestEncryptionAlgorithm();
    signature = info.getEncryptedDigest().getOctets();
    this.content = content;
    this.resultDigest = resultDigest;
  }

  protected SignerInformation(SignerInformation baseInfo) {
    this(baseInfo, baseInfo.info);
  }

  protected SignerInformation(SignerInformation baseInfo, SignerInfo info) {
    this.info = info;
    this.contentType = baseInfo.contentType;
    this.isCounterSignature = baseInfo.isCounterSignature;
    this.sID = baseInfo.sID;
    this.digestAlgorithmID = info.getDigestAlgorithm();
    this.signedAttributeSet = info.getAuthenticatedAttributes();
    this.unsignedAttributeSet = info.getUnauthenticatedAttributes();
    this.encryptionAlgorithm = info.getDigestEncryptionAlgorithm();
    this.signature = info.getEncryptedDigest().getOctets();
    this.content = baseInfo.content;
    this.resultDigest = baseInfo.resultDigest;
    this.signedAttributeValues = getSignedAttributes();
    this.unsignedAttributeValues = getUnsignedAttributes();
  }

  private byte[] encodeObj(ASN1Encodable obj) throws IOException {
    return obj != null ? obj.toASN1Primitive().getEncoded() : null;
  }

  public SignerId getSID() { return sID; }
  public boolean isCounterSignature() { return isCounterSignature; }
  public ASN1ObjectIdentifier getContentType() { return contentType; }

  public int getVersion() { return info.getVersion().intValueExact(); }

  public String getDigestAlgOID() { return digestAlgorithmID.getAlgorithm().getId(); }

  public AlgorithmIdentifier getDigestAlgorithmID() { return digestAlgorithmID; }

  public byte[] getDigestAlgParams() {
    try { return encodeObj(digestAlgorithmID.getParameters()); }
    catch (Exception e) { throw new RuntimeException("exception getting digest parameters " + e); }
  }

  public byte[] getContentDigest() {
    if (resultDigest == null) throw new IllegalStateException("method can only be called after verify.");
    return Arrays.clone(resultDigest);
  }

  public String getEncryptionAlgOID() { return encryptionAlgorithm.getAlgorithm().getId(); }

  public byte[] getEncryptionAlgParams() {
    try { return encodeObj(encryptionAlgorithm.getParameters()); }
    catch (Exception e) { throw new RuntimeException("exception getting encryption parameters " + e); }
  }

  public AttributeTable getSignedAttributes() {
    if (signedAttributeSet != null && signedAttributeValues == null) {
      signedAttributeValues = new AttributeTable(signedAttributeSet);
    }
    return signedAttributeValues;
  }

  public AttributeTable getUnsignedAttributes() {
    if (unsignedAttributeSet != null && unsignedAttributeValues == null) {
      unsignedAttributeValues = new AttributeTable(unsignedAttributeSet);
    }
    return unsignedAttributeValues;
  }

  public byte[] getSignature() {
    return Arrays.clone(signature);
  }

  public SignerInformationStore getCounterSignatures() {
    AttributeTable unsignedAttributeTable = getUnsignedAttributes();
    if (unsignedAttributeTable == null) return new SignerInformationStore(new ArrayList<>());

    List<SignerInformation> counterSignatures = new ArrayList<>();
    ASN1EncodableVector allCSAttrs = unsignedAttributeTable.getAll(CMSAttributes.counterSignature);
    for (int i = 0; i < allCSAttrs.size(); i++) {
      Attribute counterSignatureAttribute = (Attribute) allCSAttrs.get(i);
      ASN1Set values = counterSignatureAttribute.getAttrValues();
      Enumeration<?> en = values.getObjects();
      while (en.hasMoreElements()) {
        SignerInfo si = SignerInfo.getInstance(en.nextElement());
        counterSignatures.add(new SignerInformation(si, null, new CMSProcessableByteArray(getSignature()), null));
      }
    }
    return new SignerInformationStore(counterSignatures);
  }

  public byte[] getEncodedSignedAttributes() throws IOException {
    return signedAttributeSet != null ? signedAttributeSet.getEncoded(ASN1Encoding.BER) : null;
  }

  private boolean doVerify(SignerInformationVerifier verifier) throws CMSException {
    String encName = CMSSignedHelper.INSTANCE.getEncryptionAlgName(getEncryptionAlgOID());
    ContentVerifier contentVerifier;
    try {
      contentVerifier = verifier.getContentVerifier(encryptionAlgorithm, info.getDigestAlgorithm());
    } catch (OperatorCreationException e) {
      throw new CMSException("can't create content verifier: " + e.getMessage(), e);
    }

    try {
      OutputStream sigOut = contentVerifier.getOutputStream();
      if (resultDigest == null) {
        org.bouncycastle.operator.DigestCalculator calc = verifier.getDigestCalculator(digestAlgorithmID);
        if (content != null) {
          OutputStream digOut = calc.getOutputStream();
          if (signedAttributeSet == null) {
            if (contentVerifier instanceof RawContentVerifier) {
              content.write(digOut);
            } else {
              OutputStream cOut = new TeeOutputStream(digOut, sigOut);
              content.write(cOut);
              cOut.close();
            }
          } else {
            content.write(digOut);
            sigOut.write(getEncodedSignedAttributes());
          }
          digOut.close();
        } else if (signedAttributeSet != null) {
          sigOut.write(getEncodedSignedAttributes());
        } else {
          throw new CMSException("data not encapsulated in signature - use detached constructor.");
        }
        resultDigest = calc.getDigest();
      } else {
        if (signedAttributeSet == null) {
          if (content != null) content.write(sigOut);
        } else {
          sigOut.write(getEncodedSignedAttributes());
        }
      }
      sigOut.close();
    } catch (IOException e) {
      throw new CMSException("can't process mime object to create signature.", e);
    } catch (OperatorCreationException e) {
      throw new CMSException("can't create digest calculator: " + e.getMessage(), e);
    }

    verifyContentTypeAttributeValue();
    AttributeTable signedAttrTable = getSignedAttributes();
    verifyAlgorithmIdentifierProtectionAttribute(signedAttrTable);
    verifyMessageDigestAttribute();
    verifyCounterSignatureAttribute(signedAttrTable);

    try {
      if (signedAttributeSet == null && resultDigest != null) {
        if (contentVerifier instanceof RawContentVerifier) {
          RawContentVerifier rawVerifier = (RawContentVerifier) contentVerifier;
          if ("RSA".equals(encName)) {
            DigestInfo digInfo = new DigestInfo(
              new AlgorithmIdentifier(digestAlgorithmID.getAlgorithm(), DERNull.INSTANCE), resultDigest);
            return rawVerifier.verify(digInfo.getEncoded(ASN1Encoding.DER), getSignature());
          }
          return rawVerifier.verify(resultDigest, getSignature());
        }
      }
      return contentVerifier.verify(getSignature());
    } catch (IOException e) {
      throw new CMSException("can't process mime object to create signature.", e);
    }
  }

  private void verifyContentTypeAttributeValue() throws CMSException {
    ASN1Primitive validContentType = getSingleValuedSignedAttribute(CMSAttributes.contentType, "content-type");
    if (validContentType == null) {
      if (!isCounterSignature && signedAttributeSet != null) {
        throw new CMSException("The content-type attribute type MUST be present whenever signed attributes are present in signed-data");
      }
    }
  }

  private void verifyMessageDigestAttribute() throws CMSException {
    ASN1Primitive validMessageDigest = getSingleValuedSignedAttribute(CMSAttributes.messageDigest, "message-digest");
    if (validMessageDigest == null) {
      if (signedAttributeSet != null) {
        throw new CMSException("the message-digest signed attribute type MUST be present when there are any signed attributes present");
      }
    } else {
      if (!(validMessageDigest instanceof ASN1OctetString)) {
        throw new CMSException("message-digest attribute value not of ASN.1 type 'OCTET STRING'");
      }
      if (!Arrays.constantTimeAreEqual(resultDigest, ((ASN1OctetString) validMessageDigest).getOctets())) {
        throw new CMSSignerDigestMismatchException("message-digest attribute value does not match calculated value");
      }
    }
  }

  private void verifyAlgorithmIdentifierProtectionAttribute(AttributeTable signedAttrTable) throws CMSException {
    AttributeTable unsignedAttrTable = getUnsignedAttributes();
    if (unsignedAttrTable != null && unsignedAttrTable.getAll(CMSAttributes.cmsAlgorithmProtect).size() > 0) {
      throw new CMSException("A cmsAlgorithmProtect attribute MUST be a signed attribute");
    }
    if (signedAttrTable != null) {
      ASN1EncodableVector protectionAttributes = signedAttrTable.getAll(CMSAttributes.cmsAlgorithmProtect);
      if (protectionAttributes.size() > 1) {
        throw new CMSException("Only one instance of a cmsAlgorithmProtect attribute can be present");
      }
      if (protectionAttributes.size() > 0) {
        Attribute attr = Attribute.getInstance(protectionAttributes.get(0));
        if (attr.getAttrValues().size() != 1) {
          throw new CMSException("A cmsAlgorithmProtect attribute MUST contain exactly one value");
        }
        CMSAlgorithmProtection algorithmProtection = CMSAlgorithmProtection.getInstance(attr.getAttributeValues()[0]);
        if (!CMSUtils.isEquivalent(algorithmProtection.getDigestAlgorithm(), info.getDigestAlgorithm())) {
          throw new CMSException("CMS Algorithm Identifier Protection check failed for digestAlgorithm");
        }
        if (!CMSUtils.isEquivalent(algorithmProtection.getSignatureAlgorithm(), info.getDigestEncryptionAlgorithm())) {
          throw new CMSException("CMS Algorithm Identifier Protection check failed for signatureAlgorithm");
        }
      }
    }
  }

  private void verifyCounterSignatureAttribute(AttributeTable signedAttrTable) throws CMSException {
    if (signedAttrTable != null && signedAttrTable.getAll(CMSAttributes.counterSignature).size() > 0) {
      throw new CMSException("A countersignature attribute MUST NOT be a signed attribute");
    }
    AttributeTable unsignedAttrTable = getUnsignedAttributes();
    if (unsignedAttrTable != null) {
      ASN1EncodableVector csAttrs = unsignedAttrTable.getAll(CMSAttributes.counterSignature);
      for (int i = 0; i < csAttrs.size(); i++) {
        Attribute csAttr = Attribute.getInstance(csAttrs.get(i));
        if (csAttr.getAttrValues().size() < 1) {
          throw new CMSException("A countersignature attribute MUST contain at least one AttributeValue");
        }
      }
    }
  }

  public boolean verify(SignerInformationVerifier verifier) throws CMSException {
    Time signingTime = getSigningTime();
    if (verifier.hasAssociatedCertificate()) {
      if (signingTime != null) {
        org.bouncycastle.cert.X509CertificateHolder dcv = verifier.getAssociatedCertificate();
        if (!dcv.isValidOn(signingTime.getDate())) {
          throw new CMSVerifierCertificateNotValidException("verifier not valid at signingTime");
        }
      }
    }
    return doVerify(verifier);
  }

  public SignerInfo toASN1Structure() {
    return info;
  }

  private ASN1Primitive getSingleValuedSignedAttribute(ASN1ObjectIdentifier attrOID, String printableName)
    throws CMSException {
    AttributeTable unsignedAttrTable = getUnsignedAttributes();
    if (unsignedAttrTable != null && unsignedAttrTable.getAll(attrOID).size() > 0) {
      throw new CMSException("The " + printableName + " attribute MUST NOT be an unsigned attribute");
    }
    AttributeTable signedAttrTable = getSignedAttributes();
    if (signedAttrTable == null) return null;
    ASN1EncodableVector v = signedAttrTable.getAll(attrOID);
    switch (v.size()) {
      case 0: return null;
      case 1: {
        Attribute t = (Attribute) v.get(0);
        ASN1Set attrValues = t.getAttrValues();
        if (attrValues.size() != 1) {
          throw new CMSException("A " + printableName + " attribute MUST have a single attribute value");
        }
        return attrValues.getObjectAt(0).toASN1Primitive();
      }
      default:
        throw new CMSException("The SignedAttributes in a signerInfo MUST NOT include multiple instances of the "
          + printableName + " attribute");
    }
  }

  private Time getSigningTime() throws CMSException {
    ASN1Primitive validSigningTime = getSingleValuedSignedAttribute(CMSAttributes.signingTime, "signing-time");
    if (validSigningTime == null) return null;
    try {
      return Time.getInstance(validSigningTime);
    } catch (IllegalArgumentException e) {
      throw new CMSException("signing-time attribute value not a valid 'Time' structure");
    }
  }

  public static SignerInformation replaceUnsignedAttributes(SignerInformation signerInformation,
                                                             AttributeTable unsignedAttributes) {
    SignerInfo sInfo = signerInformation.info;
    ASN1Set unsignedAttr = null;
    if (unsignedAttributes != null) {
      unsignedAttr = new DERSet(unsignedAttributes.toASN1EncodableVector());
    }
    return new SignerInformation(
      new SignerInfo(sInfo.getSID(), sInfo.getDigestAlgorithm(),
        sInfo.getAuthenticatedAttributes(), sInfo.getDigestEncryptionAlgorithm(),
        sInfo.getEncryptedDigest(), unsignedAttr),
      signerInformation.contentType, signerInformation.content, null
    );
  }

  public static SignerInformation addCounterSigners(SignerInformation signerInformation,
                                                     SignerInformationStore counterSigners) {
    SignerInfo sInfo = signerInformation.info;
    AttributeTable unsignedAttr = signerInformation.getUnsignedAttributes();
    ASN1EncodableVector v = unsignedAttr != null ? unsignedAttr.toASN1EncodableVector() : new ASN1EncodableVector();

    ASN1EncodableVector sigs = new ASN1EncodableVector();
    for (SignerInformation signer : counterSigners.getSigners()) {
      sigs.add(signer.toASN1Structure());
    }
    v.add(new Attribute(CMSAttributes.counterSignature, new DERSet(sigs)));

    return new SignerInformation(
      new SignerInfo(sInfo.getSID(), sInfo.getDigestAlgorithm(),
        sInfo.getAuthenticatedAttributes(), sInfo.getDigestEncryptionAlgorithm(),
        sInfo.getEncryptedDigest(), new DERSet(v)),
      signerInformation.contentType, signerInformation.content, null
    );
  }
}
