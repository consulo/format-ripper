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
  private final SignerId _sID;
  private CMSProcessable _content;
  private byte[] _signature;
  private final ASN1ObjectIdentifier _contentType;
  private final boolean _isCounterSignature;

  private AttributeTable _signedAttributeValues;
  private AttributeTable _unsignedAttributeValues;
  private byte[] _resultDigest;
  protected final SignerInfo info;
  private final AlgorithmIdentifier _digestAlgorithmID;
  protected AlgorithmIdentifier _encryptionAlgorithm;
  protected ASN1Set _signedAttributeSet;
  protected ASN1Set _unsignedAttributeSet;

  SignerInformation(SignerInfo info, ASN1ObjectIdentifier contentType,
                    CMSProcessable content, byte[] resultDigest) {
    this.info = info;
    this._contentType = contentType;
    this._isCounterSignature = contentType == null;
    ASN1Encodable s = info.getSID().getId();
    if (info.getSID().isTagged()) {
      ASN1OctetString octs = ASN1OctetString.getInstance(s);
      _sID = new SignerId(octs.getOctets());
    } else {
      IssuerAndSerialNumber iAnds = IssuerAndSerialNumber.getInstance(s);
      _sID = new SignerId(iAnds.getName(), iAnds.getSerialNumber().getValue());
    }
    _digestAlgorithmID = info.getDigestAlgorithm();
    _signedAttributeSet = info.getAuthenticatedAttributes();
    _unsignedAttributeSet = info.getUnauthenticatedAttributes();
    _encryptionAlgorithm = info.getDigestEncryptionAlgorithm();
    _signature = info.getEncryptedDigest().getOctets();
    this._content = content;
    this._resultDigest = resultDigest;
  }

  protected SignerInformation(SignerInformation baseInfo) {
    this(baseInfo, baseInfo.info);
  }

  protected SignerInformation(SignerInformation baseInfo, SignerInfo info) {
    this.info = info;
    this._contentType = baseInfo._contentType;
    this._isCounterSignature = baseInfo._isCounterSignature;
    this._sID = baseInfo._sID;
    this._digestAlgorithmID = info.getDigestAlgorithm();
    this._signedAttributeSet = info.getAuthenticatedAttributes();
    this._unsignedAttributeSet = info.getUnauthenticatedAttributes();
    this._encryptionAlgorithm = info.getDigestEncryptionAlgorithm();
    this._signature = info.getEncryptedDigest().getOctets();
    this._content = baseInfo._content;
    this._resultDigest = baseInfo._resultDigest;
    this._signedAttributeValues = getSignedAttributes();
    this._unsignedAttributeValues = getUnsignedAttributes();
  }

  private byte[] encodeObj(ASN1Encodable obj) throws IOException {
    return obj != null ? obj.toASN1Primitive().getEncoded() : null;
  }

  public SignerId getSID() { return _sID; }
  public boolean isCounterSignature() { return _isCounterSignature; }
  public ASN1ObjectIdentifier getContentType() { return _contentType; }

  public int getVersion() { return info.getVersion().intValueExact(); }

  public String getDigestAlgOID() { return _digestAlgorithmID.getAlgorithm().getId(); }

  public AlgorithmIdentifier getDigestAlgorithmID() { return _digestAlgorithmID; }

  public byte[] getDigestAlgParams() {
    try { return encodeObj(_digestAlgorithmID.getParameters()); }
    catch (Exception e) { throw new RuntimeException("exception getting digest parameters " + e); }
  }

  public byte[] getContentDigest() {
    if (_resultDigest == null) throw new IllegalStateException("method can only be called after verify.");
    return Arrays.clone(_resultDigest);
  }

  public String getEncryptionAlgOID() { return _encryptionAlgorithm.getAlgorithm().getId(); }

  public byte[] getEncryptionAlgParams() {
    try { return encodeObj(_encryptionAlgorithm.getParameters()); }
    catch (Exception e) { throw new RuntimeException("exception getting encryption parameters " + e); }
  }

  public AttributeTable getSignedAttributes() {
    if (_signedAttributeSet != null && _signedAttributeValues == null) {
      _signedAttributeValues = new AttributeTable(_signedAttributeSet);
    }
    return _signedAttributeValues;
  }

  public AttributeTable getUnsignedAttributes() {
    if (_unsignedAttributeSet != null && _unsignedAttributeValues == null) {
      _unsignedAttributeValues = new AttributeTable(_unsignedAttributeSet);
    }
    return _unsignedAttributeValues;
  }

  // Kotlin-style accessors
  public AttributeTable signedAttributes() { return getSignedAttributes(); }
  public AttributeTable unsignedAttributes() { return getUnsignedAttributes(); }

  public byte[] getSignature() {
    return Arrays.clone(_signature);
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
    return _signedAttributeSet != null ? _signedAttributeSet.getEncoded(ASN1Encoding.BER) : null;
  }

  private boolean doVerify(SignerInformationVerifier verifier) throws CMSException {
    String encName = CMSSignedHelper.INSTANCE.getEncryptionAlgName(getEncryptionAlgOID());
    ContentVerifier contentVerifier;
    try {
      contentVerifier = verifier.getContentVerifier(_encryptionAlgorithm, info.getDigestAlgorithm());
    } catch (OperatorCreationException e) {
      throw new CMSException("can't create content verifier: " + e.getMessage(), e);
    }

    try {
      OutputStream sigOut = contentVerifier.getOutputStream();
      if (_resultDigest == null) {
        org.bouncycastle.operator.DigestCalculator calc = verifier.getDigestCalculator(_digestAlgorithmID);
        if (_content != null) {
          OutputStream digOut = calc.getOutputStream();
          if (_signedAttributeSet == null) {
            if (contentVerifier instanceof RawContentVerifier) {
              _content.write(digOut);
            } else {
              OutputStream cOut = new TeeOutputStream(digOut, sigOut);
              _content.write(cOut);
              cOut.close();
            }
          } else {
            _content.write(digOut);
            sigOut.write(getEncodedSignedAttributes());
          }
          digOut.close();
        } else if (_signedAttributeSet != null) {
          sigOut.write(getEncodedSignedAttributes());
        } else {
          throw new CMSException("data not encapsulated in signature - use detached constructor.");
        }
        _resultDigest = calc.getDigest();
      } else {
        if (_signedAttributeSet == null) {
          if (_content != null) _content.write(sigOut);
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
      if (_signedAttributeSet == null && _resultDigest != null) {
        if (contentVerifier instanceof RawContentVerifier) {
          RawContentVerifier rawVerifier = (RawContentVerifier) contentVerifier;
          if ("RSA".equals(encName)) {
            DigestInfo digInfo = new DigestInfo(
              new AlgorithmIdentifier(_digestAlgorithmID.getAlgorithm(), DERNull.INSTANCE), _resultDigest);
            return rawVerifier.verify(digInfo.getEncoded(ASN1Encoding.DER), getSignature());
          }
          return rawVerifier.verify(_resultDigest, getSignature());
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
      if (!_isCounterSignature && _signedAttributeSet != null) {
        throw new CMSException("The content-type attribute type MUST be present whenever signed attributes are present in signed-data");
      }
    }
  }

  private void verifyMessageDigestAttribute() throws CMSException {
    ASN1Primitive validMessageDigest = getSingleValuedSignedAttribute(CMSAttributes.messageDigest, "message-digest");
    if (validMessageDigest == null) {
      if (_signedAttributeSet != null) {
        throw new CMSException("the message-digest signed attribute type MUST be present when there are any signed attributes present");
      }
    } else {
      if (!(validMessageDigest instanceof ASN1OctetString)) {
        throw new CMSException("message-digest attribute value not of ASN.1 type 'OCTET STRING'");
      }
      if (!Arrays.constantTimeAreEqual(_resultDigest, ((ASN1OctetString) validMessageDigest).getOctets())) {
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
      signerInformation._contentType, signerInformation._content, null
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
      signerInformation._contentType, signerInformation._content, null
    );
  }
}
