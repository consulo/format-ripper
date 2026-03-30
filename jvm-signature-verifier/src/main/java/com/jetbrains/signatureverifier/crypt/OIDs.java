package com.jetbrains.signatureverifier.crypt;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public final class OIDs {
  public static final ASN1ObjectIdentifier SPC_INDIRECT_DATA = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.1.4");
  public static final ASN1ObjectIdentifier SPC_NESTED_SIGNATURE = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.4.1");
  public static final ASN1ObjectIdentifier SIGNING_TIME = new ASN1ObjectIdentifier("1.2.840.113549.1.9.5");
  public static final ASN1ObjectIdentifier MS_COUNTER_SIGN = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.3.3.1");
  public static final ASN1ObjectIdentifier TIMESTAMP_TOKEN = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14");
  public static final ASN1ObjectIdentifier EXTENDED_KEY_USAGE = new ASN1ObjectIdentifier("2.5.29.37");
  public static final ASN1ObjectIdentifier APPLE_CERTIFICATE_EXTENSION_CODE_SIGNING = new ASN1ObjectIdentifier("1.2.840.113635.100.6.1.13");
  public static final ASN1ObjectIdentifier APPLE_CERTIFICATE_EXTENSION_KEXT_SIGNING = new ASN1ObjectIdentifier("1.2.840.113635.100.6.1.18");
  public static final ASN1ObjectIdentifier OCSP = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1");
  public static final ASN1ObjectIdentifier SPC_SIPINFO_OBJID = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.1.30");

  private OIDs() {
  }
}
