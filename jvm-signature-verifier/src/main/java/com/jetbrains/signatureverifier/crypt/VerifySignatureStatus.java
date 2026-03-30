package com.jetbrains.signatureverifier.crypt;

public enum VerifySignatureStatus {
  Valid,
  InvalidSignature,
  InvalidChain,
  InvalidTimestamp
}
