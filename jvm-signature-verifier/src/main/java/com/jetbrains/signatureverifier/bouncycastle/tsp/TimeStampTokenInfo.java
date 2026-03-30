package com.jetbrains.signatureverifier.bouncycastle.tsp;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.tsp.Accuracy;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.tsp.GenTimeAccuracy;
import org.bouncycastle.tsp.TSPException;

import java.io.IOException;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;

public class TimeStampTokenInfo {
  TSTInfo tstInfo;
  Date genTime;

  TimeStampTokenInfo(TSTInfo tstInfo) throws TSPException {
    this.tstInfo = tstInfo;
    try {
      genTime = tstInfo.getGenTime().getDate();
    } catch (ParseException e) {
      throw new TSPException("unable to parse genTime field");
    }
  }

  public Date getGenTime() { return genTime; }

  public boolean isOrdered() { return tstInfo.getOrdering().isTrue(); }

  public Accuracy getAccuracy() { return tstInfo.getAccuracy(); }

  public GenTimeAccuracy getGenTimeAccuracy() {
    Accuracy acc = getAccuracy();
    return acc != null ? new GenTimeAccuracy(acc) : null;
  }

  public ASN1ObjectIdentifier getPolicy() { return tstInfo.getPolicy(); }

  public BigInteger getSerialNumber() { return tstInfo.getSerialNumber().getValue(); }

  public GeneralName getTsa() { return tstInfo.getTsa(); }

  public Extensions getExtensions() { return tstInfo.getExtensions(); }

  public BigInteger getNonce() {
    return tstInfo.getNonce() != null ? tstInfo.getNonce().getValue() : null;
  }

  public AlgorithmIdentifier getHashAlgorithm() {
    return tstInfo.getMessageImprint().getHashAlgorithm();
  }

  public ASN1ObjectIdentifier getMessageImprintAlgOID() {
    return tstInfo.getMessageImprint().getHashAlgorithm().getAlgorithm();
  }

  public byte[] getMessageImprintDigest() {
    return tstInfo.getMessageImprint().getHashedMessage();
  }

  public byte[] getEncoded() throws IOException {
    return tstInfo.getEncoded();
  }

  @Deprecated
  public TSTInfo toTSTInfo() { return tstInfo; }

  public TSTInfo toASN1Structure() { return tstInfo; }
}
