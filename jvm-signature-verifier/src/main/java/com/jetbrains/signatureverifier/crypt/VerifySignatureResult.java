package com.jetbrains.signatureverifier.crypt;

public class VerifySignatureResult {
  public static final VerifySignatureResult Valid = new VerifySignatureResult(VerifySignatureStatus.Valid);

  private final VerifySignatureStatus status;
  private final String message;

  public VerifySignatureResult(VerifySignatureStatus status) {
    this(status, null);
  }

  public VerifySignatureResult(VerifySignatureStatus status, String message) {
    this.status = status;
    this.message = message;
  }

  public VerifySignatureStatus getStatus() {
    return status;
  }

  public String getMessage() {
    return message;
  }

  public boolean isNotValid() {
    return status != VerifySignatureStatus.Valid;
  }

  public static VerifySignatureResult invalidChain(String message) {
    return new VerifySignatureResult(VerifySignatureStatus.InvalidChain, message);
  }
}
