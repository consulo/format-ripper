package com.jetbrains.signatureverifier.powershell;

import com.jetbrains.signatureverifier.SignatureData;
import com.jetbrains.signatureverifier.bouncycastle.cms.CMSSignedData;
import com.jetbrains.signatureverifier.crypt.OIDs;
import com.jetbrains.signatureverifier.crypt.VerifySignatureResult;
import com.jetbrains.signatureverifier.crypt.VerifySignatureStatus;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSTypedData;

import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

public class PowerShellScriptFile {
  private final PowerShellScript script;

  public PowerShellScriptFile(SeekableByteChannel channel) throws IOException {
    script = new PowerShellScript(Channels.newInputStream(channel));
  }

  public PowerShellScriptFile(InputStream stream) throws IOException {
    script = new PowerShellScript(stream);
  }

  public SignatureData GetSignatureData() {
    byte[] bytes = script.decodeSignatureBlock();
    if (bytes == null) return SignatureData.Empty;
    return new SignatureData(null, bytes);
  }

  /**
   * Computes hash of the content, without signature.
   * Useful to verify that hash stored in signature is the same as content hash.
   */
  public byte[] ComputeHash(String algName) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance(algName);
    return script.computeDigest(digest);
  }

  public String GetContentWithoutSignature() {
    return script.getContentWithoutSignatureBlock();
  }

  private static VerifySignatureResult invalid(String message) {
    return new VerifySignatureResult(VerifySignatureStatus.InvalidSignature, message);
  }

  /**
   * Returns VerifySignatureResult with either Valid or InvalidSignature status
   */
  public VerifySignatureResult VerifyContentHash(CMSSignedData signedData, PowerShellScriptFile file) {
    try {
      if (signedData.getDigestAlgorithmIDs().size() != 1) {
        return invalid("Signed Data must contain exactly one DigestAlgorithm, got: " + signedData.getDigestAlgorithmIDs());
      }

      org.bouncycastle.asn1.ASN1ObjectIdentifier signedDataAlgorithm =
        signedData.getDigestAlgorithmIDs().iterator().next().getAlgorithm();

      CMSTypedData signedContent = signedData.getSignedContent();
      DigestInfo digestInfo = signedContent != null ? getSpcIndirectDataContent(signedContent) : null;
      if (digestInfo == null) {
        return invalid("Signed Data does not contain SpcIndirectData structure (" + OIDs.SPC_INDIRECT_DATA + ") with DigestInfo");
      }

      // Check that SpcIndirectContent DigestAlgorithm equals CMSSignedData algorithm
      if (!digestInfo.getAlgorithmId().getAlgorithm().equals(signedDataAlgorithm)) {
        return invalid("Signed Data algorithm does not match with spcDigestAlgorithm");
      }

      // Check that SignerInfo DigestAlgorithm equals CMSSignedData algorithm
      if (signedData.getSignerInfos().size() != 1) {
        return invalid("Signed Data must contain exactly one SignerInfo. Got: " + signedData.getSignerInfos().getSigners());
      }

      com.jetbrains.signatureverifier.bouncycastle.cms.SignerInformation signerInformation =
        signedData.getSignerInfos().iterator().next();
      if (!signerInformation.getDigestAlgorithmID().getAlgorithm().equals(signedDataAlgorithm)) {
        return invalid("Signed Data algorithm doesn't match with SignerInformation algorithm");
      }

      // Check the embedded hash in spcIndirectContent matches with the computed hash of the file
      if (!Arrays.equals(file.ComputeHash(signedDataAlgorithm.getId()), digestInfo.getDigest())) {
        return invalid("The embedded hash in the SignedData is not equal to the computed hash of file content");
      }

      return new VerifySignatureResult(VerifySignatureStatus.Valid);
    } catch (CMSException | NoSuchAlgorithmException e) {
      return invalid("Error verifying signature: " + e.getMessage());
    }
  }

  // See SpcIndirectDataToken.cs
  private static DigestInfo getSpcIndirectDataContent(CMSTypedData contentInfo) throws CMSException {
    if (!OIDs.SPC_INDIRECT_DATA.equals(contentInfo.getContentType())) {
      return null;
    }
    Object content = contentInfo.getContent();
    if (!(content instanceof ASN1Sequence)) return null;
    ASN1Sequence obj = (ASN1Sequence) content;

    List<ASN1Sequence> sequences = new ArrayList<>();
    Enumeration<?> objects = obj.getObjects();
    while (objects.hasMoreElements()) {
      Object element = objects.nextElement();
      if (element instanceof ASN1Encodable) {
        ASN1Encodable enc = (ASN1Encodable) element;
        if (enc.toASN1Primitive() instanceof ASN1Sequence) {
          sequences.add((ASN1Sequence) enc.toASN1Primitive());
        }
      }
    }

    if (sequences.size() != 2) {
      throw new CMSException("Incorrect SpcIndirectData structure: must be a sequence of two nested sequences, got: " + sequences.size());
    }
    Enumeration<?> firstObjects = sequences.get(0).getObjects();
    Object firstElement = firstObjects.hasMoreElements() ? firstObjects.nextElement() : null;
    if (!OIDs.SPC_SIPINFO_OBJID.equals(firstElement)) {
      throw new CMSException("Incorrect SpcIndirectData structure: first nested sequence must contain SPC_SIPINFO_OBJID, got: " + firstElement);
    }
    return DigestInfo.getInstance(sequences.get(1));
  }
}
