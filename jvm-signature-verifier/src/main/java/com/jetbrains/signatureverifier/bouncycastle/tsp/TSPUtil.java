package com.jetbrains.signatureverifier.bouncycastle.tsp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPIOException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TSPUtil {
  private static final List<Object> EMPTY_LIST = Collections.unmodifiableList(new ArrayList<>());
  private static final Map<String, Integer> digestLengths = new HashMap<>();
  private static final Map<String, String> digestNames = new HashMap<>();

  static {
    digestLengths.put(PKCSObjectIdentifiers.md5.getId(), Integers.valueOf(16));
    digestLengths.put(OIWObjectIdentifiers.idSHA1.getId(), Integers.valueOf(20));
    digestLengths.put(NISTObjectIdentifiers.id_sha224.getId(), Integers.valueOf(28));
    digestLengths.put(NISTObjectIdentifiers.id_sha256.getId(), Integers.valueOf(32));
    digestLengths.put(NISTObjectIdentifiers.id_sha384.getId(), Integers.valueOf(48));
    digestLengths.put(NISTObjectIdentifiers.id_sha512.getId(), Integers.valueOf(64));
    digestLengths.put(TeleTrusTObjectIdentifiers.ripemd128.getId(), Integers.valueOf(16));
    digestLengths.put(TeleTrusTObjectIdentifiers.ripemd160.getId(), Integers.valueOf(20));
    digestLengths.put(TeleTrusTObjectIdentifiers.ripemd256.getId(), Integers.valueOf(32));
    digestLengths.put(CryptoProObjectIdentifiers.gostR3411.getId(), Integers.valueOf(32));
    digestLengths.put(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.getId(), Integers.valueOf(32));
    digestLengths.put(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.getId(), Integers.valueOf(64));
    digestLengths.put(GMObjectIdentifiers.sm3.getId(), Integers.valueOf(32));

    digestNames.put(PKCSObjectIdentifiers.md5.getId(), "MD5");
    digestNames.put(OIWObjectIdentifiers.idSHA1.getId(), "SHA1");
    digestNames.put(NISTObjectIdentifiers.id_sha224.getId(), "SHA224");
    digestNames.put(NISTObjectIdentifiers.id_sha256.getId(), "SHA256");
    digestNames.put(NISTObjectIdentifiers.id_sha384.getId(), "SHA384");
    digestNames.put(NISTObjectIdentifiers.id_sha512.getId(), "SHA512");
    digestNames.put(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "SHA1");
    digestNames.put(PKCSObjectIdentifiers.sha224WithRSAEncryption.getId(), "SHA224");
    digestNames.put(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), "SHA256");
    digestNames.put(PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(), "SHA384");
    digestNames.put(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(), "SHA512");
    digestNames.put(TeleTrusTObjectIdentifiers.ripemd128.getId(), "RIPEMD128");
    digestNames.put(TeleTrusTObjectIdentifiers.ripemd160.getId(), "RIPEMD160");
    digestNames.put(TeleTrusTObjectIdentifiers.ripemd256.getId(), "RIPEMD256");
    digestNames.put(CryptoProObjectIdentifiers.gostR3411.getId(), "GOST3411");
    digestNames.put(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.getId(), "GOST3411-2012-256");
    digestNames.put(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.getId(), "GOST3411-2012-512");
    digestNames.put(GMObjectIdentifiers.sm3.getId(), "SM3");
  }

  public static List<TimeStampToken> getSignatureTimestamps(
    SignerInformation signerInfo, DigestCalculatorProvider digCalcProvider) throws TSPValidationException {
    List<TimeStampToken> timestamps = new ArrayList<>();
    AttributeTable unsignedAttrs = signerInfo.getUnsignedAttributes();
    if (unsignedAttrs != null) {
      org.bouncycastle.asn1.ASN1EncodableVector allTSAttrs =
        unsignedAttrs.getAll(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
      for (int i = 0; i < allTSAttrs.size(); i++) {
        Attribute tsAttr = (Attribute) allTSAttrs.get(i);
        org.bouncycastle.asn1.ASN1Set tsAttrValues = tsAttr.getAttrValues();
        for (int j = 0; j < tsAttrValues.size(); j++) {
          try {
            ContentInfo contentInfo = ContentInfo.getInstance(tsAttrValues.getObjectAt(j));
            TimeStampToken timeStampToken = new TimeStampToken(contentInfo);
            TimeStampTokenInfo tstInfo = timeStampToken.timeStampInfo;
            org.bouncycastle.operator.DigestCalculator digCalc = digCalcProvider.get(tstInfo.getHashAlgorithm());
            java.io.OutputStream dOut = digCalc.getOutputStream();
            dOut.write(signerInfo.getSignature());
            dOut.close();
            byte[] expectedDigest = digCalc.getDigest();
            if (!Arrays.constantTimeAreEqual(expectedDigest, tstInfo.getMessageImprintDigest())) {
              throw new TSPValidationException("Incorrect digest in message imprint");
            }
            timestamps.add(timeStampToken);
          } catch (OperatorCreationException e) {
            throw new TSPValidationException("Unknown hash algorithm specified in timestamp");
          } catch (Exception e) {
            throw new TSPValidationException("Timestamp could not be parsed");
          }
        }
      }
    }
    return timestamps;
  }

  public static void validateCertificate(X509CertificateHolder cert) throws TSPValidationException {
    org.bouncycastle.asn1.x509.Extension ext = cert.getExtension(Extension.extendedKeyUsage);
    if (ext == null)
      throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension.");
    ExtendedKeyUsage extKey = ExtendedKeyUsage.getInstance(ext.getParsedValue());
    if (!extKey.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping) || extKey.size() != 1) {
      throw new TSPValidationException("ExtendedKeyUsage not solely time stamping.");
    }
  }

  public static int getDigestLength(String digestAlgOID) throws TSPException {
    Integer length = digestLengths.get(digestAlgOID);
    if (length != null) return length;
    throw new TSPException("digest algorithm cannot be found.");
  }

  public static List<?> getExtensionOIDs(org.bouncycastle.asn1.x509.Extensions extensions) {
    if (extensions == null) return EMPTY_LIST;
    return Collections.unmodifiableList(java.util.Arrays.asList(extensions.getExtensionOIDs()));
  }

  public static void addExtension(ExtensionsGenerator extGenerator, ASN1ObjectIdentifier oid,
                                   boolean isCritical, ASN1Encodable value) throws TSPIOException {
    try {
      extGenerator.addExtension(oid, isCritical, value);
    } catch (IOException e) {
      throw new TSPIOException("cannot encode extension: " + e.getMessage(), e);
    }
  }
}
