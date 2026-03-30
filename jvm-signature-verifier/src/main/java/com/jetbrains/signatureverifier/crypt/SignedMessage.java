package com.jetbrains.signatureverifier.crypt;

import com.jetbrains.signatureverifier.SignatureData;
import com.jetbrains.signatureverifier.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSProcessableByteArray;

import java.io.IOException;

public class SignedMessage {
  public final CMSSignedData SignedData;

  public static SignedMessage CreateInstance(SignatureData signatureData) throws Exception {
    if (signatureData.IsEmpty())
      throw new IllegalArgumentException("signatureData is empty");
    if (signatureData.HasAttachedSignedData())
      return new SignedMessage(signatureData.getSignedData(), signatureData.getCmsData());
    return new SignedMessage(signatureData.getCmsData());
  }

  private SignedMessage(byte[] pkcs7Data) throws Exception {
    ASN1InputStream asnStream = new ASN1InputStream(pkcs7Data);
    ContentInfo pkcs7 = ContentInfo.getInstance(asnStream.readObject());
    SignedData = new CMSSignedData(pkcs7);
  }

  private SignedMessage(byte[] signedData, byte[] pkcs7Data) throws Exception {
    CMSProcessableByteArray signedContent = new CMSProcessableByteArray(signedData);
    try {
      ASN1InputStream asnStream = new ASN1InputStream(pkcs7Data);
      ContentInfo pkcs7 = ContentInfo.getInstance(asnStream.readObject());
      SignedData = new CMSSignedData(signedContent, pkcs7);
    } catch (IOException ex) {
      throw new Exception("Invalid signature format", ex);
    }
  }

  public SignedMessage(ASN1Object obj) throws Exception {
    ContentInfo pkcs7 = ContentInfo.getInstance(obj);
    SignedData = new CMSSignedData(pkcs7);
  }
}
