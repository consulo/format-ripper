package com.jetbrains.signatureverifier.tests.authenticode;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.x509.DigestInfo;

public class SpcIndirectDataContent implements ASN1Encodable {
  private final SpcAttributeOptional data;
  private final DigestInfo messageDigest;

  public SpcIndirectDataContent(SpcAttributeOptional data, DigestInfo messageDigest) {
    this.data = data;
    this.messageDigest = messageDigest;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new BERSequence(vec(data, messageDigest));
  }

  static ASN1EncodableVector vec(ASN1Encodable... items) {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.addAll(items);
    return v;
  }
}
