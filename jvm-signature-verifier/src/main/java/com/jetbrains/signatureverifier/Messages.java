package com.jetbrains.signatureverifier;

public final class Messages {
  public static final String unknown_certificate_revocation_status = "Unknown certificate revocation status";
  public static final String invalid_ocsp_response = "Invalid OCSP response";
  public static final String unable_determin_certificate_revocation_status = "Unable to determine certificate revocation status";
  public static final String certificate_revoked = "Certificate has been revoked at {0}. {1}";
  public static final String signer_cert_not_found = "Signer's certificate not found";

  private Messages() {
  }
}
