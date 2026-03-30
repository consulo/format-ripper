package com.jetbrains.signatureverifier;

public class SignatureData {
  public static final SignatureData Empty = new SignatureData(null, null);

  private final byte[] signedData;
  private final byte[] cmsData;

  public SignatureData(byte[] signedData, byte[] cmsData) {
    this.signedData = signedData;
    this.cmsData = cmsData;
  }

  public byte[] getSignedData() {
    return signedData;
  }

  public byte[] getCmsData() {
    return cmsData;
  }

  public boolean isEmpty() {
    return cmsData == null;
  }

  public boolean hasAttachedSignedData() {
    return signedData != null;
  }
}
