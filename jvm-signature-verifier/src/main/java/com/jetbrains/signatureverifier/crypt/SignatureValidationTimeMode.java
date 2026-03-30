package com.jetbrains.signatureverifier.crypt;

public enum SignatureValidationTimeMode {
  /** Extract a timestamp or signing time (1.2.840.113549.1.9.5) from a signed message */
  Timestamp,

  /** Validate signatures in the current time */
  Current,

  /** Validate signatures in the particular time */
  SignValidationTime
}
