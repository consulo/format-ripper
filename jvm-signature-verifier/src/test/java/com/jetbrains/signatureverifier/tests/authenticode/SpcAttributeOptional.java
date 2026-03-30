package com.jetbrains.signatureverifier.tests.authenticode;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERSequence;

public class SpcAttributeOptional implements ASN1Encodable {
  private final ASN1ObjectIdentifier type;
  private final ASN1Encodable value;

  public SpcAttributeOptional(ASN1ObjectIdentifier type, ASN1Encodable value) {
    this.type = type;
    this.value = value;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = SpcIndirectDataContent.vec(type);
    if (value != null) v.add(value);
    return new BERSequence(v);
  }
}
