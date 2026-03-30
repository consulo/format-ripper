package com.jetbrains.signatureverifier.tests.authenticode;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERTaggedObject;

public class SpcPeImageData implements ASN1Encodable {
  private final DERBitString flags = new DERBitString(new byte[0]);
  private final SpcLink file = new SpcLink();

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new BERSequence(SpcIndirectDataContent.vec(flags, new DERTaggedObject(0, file)));
  }
}
