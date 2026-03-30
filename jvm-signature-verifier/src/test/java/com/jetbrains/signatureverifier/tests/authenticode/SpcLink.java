package com.jetbrains.signatureverifier.tests.authenticode;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERTaggedObject;

public class SpcLink implements ASN1Encodable, ASN1Choice {
  private final SpcString file = new SpcString("");

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERTaggedObject(false, 2, file);
  }
}
