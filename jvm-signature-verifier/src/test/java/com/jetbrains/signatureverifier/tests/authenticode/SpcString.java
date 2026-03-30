package com.jetbrains.signatureverifier.tests.authenticode;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERTaggedObject;

public class SpcString implements ASN1Encodable, ASN1Choice {
  private final DERBMPString unicode;

  public SpcString(String str) {
    this.unicode = new DERBMPString(str);
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERTaggedObject(false, 0, unicode);
  }
}
