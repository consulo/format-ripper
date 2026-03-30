package com.jetbrains.signatureverifier.crypt;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;

import java.util.Iterator;
import java.util.NoSuchElementException;

class ASN1EncodableVectorIterator implements Iterator<ASN1Encodable> {
  private final ASN1EncodableVector encodableVector;
  private int idx = 0;
  private final int size;

  ASN1EncodableVectorIterator(ASN1EncodableVector encodableVector) {
    this.encodableVector = encodableVector;
    this.size = encodableVector.size();
  }

  @Override
  public boolean hasNext() {
    return idx < size;
  }

  @Override
  public ASN1Encodable next() {
    if (!hasNext()) throw new NoSuchElementException();
    return encodableVector.get(idx++);
  }
}
