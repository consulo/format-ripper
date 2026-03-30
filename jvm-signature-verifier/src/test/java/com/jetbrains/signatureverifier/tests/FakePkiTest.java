package com.jetbrains.signatureverifier.tests;

import com.jetbrains.signatureverifier.PeFile;
import com.jetbrains.signatureverifier.crypt.*;
import com.jetbrains.signatureverifier.tests.authenticode.SpcAttributeOptional;
import com.jetbrains.signatureverifier.tests.authenticode.SpcIndirectDataContent;
import com.jetbrains.signatureverifier.tests.authenticode.SpcPeImageData;
import com.jetbrains.util.filetype.io.ReadUtils;
import com.jetbrains.util.filetype.io.SeekOrigin;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.channels.SeekableByteChannel;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.AbstractMap;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Stream;

class FakePkiTest {
  private final Clock localClock = Clock.systemDefaultZone();

  private Date nowPlusDays(long days) {
    return Utils.ConvertToDate(LocalDateTime.now(localClock).plusDays(days));
  }

  private Date nowPlusSeconds(long seconds) {
    return Utils.ConvertToDate(LocalDateTime.now(localClock).plusSeconds(seconds));
  }

  @ParameterizedTest
  @MethodSource("FakePkiTestProvider")
  void InvalidSignatureNoSignerCert(String peResourceName) throws Exception {
    FakePki pki = FakePki.CreateRoot("fakeroot", nowPlusDays(-1), nowPlusDays(10));
    AbstractMap.SimpleImmutableEntry<KeyPair, X509CertificateHolder> pair =
      pki.Enroll("sub", nowPlusDays(0), nowPlusDays(9), false);
    KeyPair keyPair = pair.getKey();
    X509CertificateHolder cert = pair.getValue();

    try (SeekableByteChannel peStream = TestUtil.getTestByteChannelCopy("pe", peResourceName);
         SeekableByteChannel signedPeStream = signPe(peStream, keyPair.getPrivate(), cert, false)) {
      PeFile peFile = new PeFile(signedPeStream);
      var signatureData = peFile.GetSignatureData();
      var signedMessage = SignedMessage.CreateInstance(signatureData);

      try (InputStream signRootCertStore = getRootStoreStream(pki.getCertificate())) {
        SignatureVerificationParams verificationParams = new SignatureVerificationParams(signRootCertStore, null, true, false);
        SignedMessageVerifier signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
        var res = signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
        Assertions.assertEquals(VerifySignatureStatus.InvalidSignature, res.Status());
      }
    }
  }

  @ParameterizedTest
  @MethodSource("FakePkiTestProvider")
  void InvalidChainCertRevoked(String peResourceName) throws Exception {
    FakePki pki = FakePki.CreateRoot("fakeroot", nowPlusDays(-1), nowPlusDays(10));
    AbstractMap.SimpleImmutableEntry<KeyPair, X509CertificateHolder> pair =
      pki.Enroll("sub", nowPlusDays(0), nowPlusDays(9), true);
    KeyPair keyPair = pair.getKey();
    X509CertificateHolder cert = pair.getValue();

    pki.Revoke(cert, true);
    Thread.sleep(2000);

    CrlCacheFileSystem crlCache = Mockito.mock(CrlCacheFileSystem.class);
    Mockito.when(crlCache.GetCrls(Mockito.anyString())).thenReturn(Collections.emptyList());
    Mockito.doNothing().when(crlCache).UpdateCrls(Mockito.anyString(), Mockito.anyList());

    CrlSource crlSource = Mockito.mock(CrlSource.class);
    Mockito.when(crlSource.GetCrlAsync(Mockito.anyString()))
      .thenReturn(pki.getCrl() != null ? pki.getCrl().getEncoded() : null);

    try (SeekableByteChannel peStream = TestUtil.getTestByteChannelCopy("pe", peResourceName);
         SeekableByteChannel signedPeStream = signPe(peStream, keyPair.getPrivate(), cert)) {
      PeFile peFile = new PeFile(signedPeStream);
      var signatureData = peFile.GetSignatureData();
      var signedMessage = SignedMessage.CreateInstance(signatureData);

      try (InputStream signRootCertStore = getRootStoreStream(pki.getCertificate())) {
        SignatureVerificationParams verificationParams = new SignatureVerificationParams(signRootCertStore, null, true, true);
        SignedMessageVerifier signedMessageVerifier =
          new SignedMessageVerifier(new CrlProvider(crlSource, crlCache, ConsoleLogger.Instance), ConsoleLogger.Instance);
        var res = signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
        Assertions.assertEquals(VerifySignatureStatus.InvalidChain, res.Status());
      }
    }
  }

  @ParameterizedTest
  @MethodSource("FakePkiTestProvider")
  void InvalidChainCertOutdated(String peResourceName) throws Exception {
    FakePki pki = FakePki.CreateRoot("fakeroot", nowPlusDays(-1), nowPlusDays(10));
    AbstractMap.SimpleImmutableEntry<KeyPair, X509CertificateHolder> pair =
      pki.Enroll("sub", nowPlusDays(0), nowPlusSeconds(1), false);
    KeyPair keyPair = pair.getKey();
    X509CertificateHolder cert = pair.getValue();

    Thread.sleep(2000);

    try (SeekableByteChannel peStream = TestUtil.getTestByteChannelCopy("pe", peResourceName);
         SeekableByteChannel signedPeStream = signPe(peStream, keyPair.getPrivate(), cert)) {
      PeFile peFile = new PeFile(signedPeStream);
      var signatureData = peFile.GetSignatureData();
      var signedMessage = SignedMessage.CreateInstance(signatureData);
      SignatureVerificationParams verificationParams = new SignatureVerificationParams(null, null, false, false);
      SignedMessageVerifier signedMessageVerifier = new SignedMessageVerifier(ConsoleLogger.Instance);
      var res = signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
      Assertions.assertEquals(VerifySignatureStatus.InvalidSignature, res.Status());
    }
  }

  private SeekableByteChannel signPe(SeekableByteChannel peStream, PrivateKey privateKey,
                                      X509CertificateHolder cert) throws Exception {
    return signPe(peStream, privateKey, cert, true);
  }

  private SeekableByteChannel signPe(SeekableByteChannel peStream, PrivateKey privateKey,
                                      X509CertificateHolder cert, boolean addSignerCert) throws Exception {
    CMSSignedDataGenerator cmsGen = new CMSSignedDataGenerator();
    var sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);
    cmsGen.addSignerInfoGenerator(
      new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
        .build(sha1Signer, cert)
    );
    if (addSignerCert) {
      cmsGen.addCertificates(new CollectionStore<>(Collections.singletonList(cert)));
    }

    PeFile peFile = new PeFile(peStream);
    ASN1Encodable content = createCmsSignedData(peFile);
    byte[] contentData = content.toASN1Primitive().getEncoded();
    var cmsSignedData = cmsGen.generate(new CMSProcessableByteArray(contentData), true);

    ReadUtils.seek(peStream, 0, SeekOrigin.Begin);
    byte[] peBytes = ReadUtils.readToEnd(peStream);
    SeekableInMemoryByteChannel signedPeStream = new SeekableInMemoryByteChannel(peBytes);

    BinaryWriter writer = new BinaryWriter(signedPeStream);
    byte[] encodedCmsSignedData = cmsSignedData.getEncoded();
    ReadUtils.seek(signedPeStream, 0, SeekOrigin.End);
    long attributeCertificateTableOffset = signedPeStream.position();

    // write attribute certificate table
    writer.Write(encodedCmsSignedData.length);     // dwLength
    writer.Write((short) 0x0200);                  // wRevision = WIN_CERT_REVISION_2_0
    writer.Write((short) 2);                       // wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA
    writer.Write(encodedCmsSignedData);            // bCertificate

    // write new ImageDirectoryEntrySecurity
    ReadUtils.seek(signedPeStream, peFile.ImageDirectoryEntrySecurityOffset(), SeekOrigin.Begin);
    writer.Write((int) attributeCertificateTableOffset);
    writer.Write(encodedCmsSignedData.length);

    return signedPeStream;
  }

  private ASN1Encodable createCmsSignedData(PeFile peFile) throws Exception {
    DigestInfo digestInfo = new DigestInfo(
      new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE),
      peFile.ComputeHash("sha1")
    );
    SpcAttributeOptional data = new SpcAttributeOptional(
      new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.1.15"), new SpcPeImageData()
    );
    return new SpcIndirectDataContent(data, digestInfo);
  }

  private static InputStream getRootStoreStream(X509CertificateHolder cert) throws Exception {
    CMSSignedDataGenerator cmsGen = new CMSSignedDataGenerator();
    cmsGen.addCertificate(cert);
    var cmsSignedData = cmsGen.generate(new CMSProcessableByteArray(new byte[0]), false);
    return new ByteArrayInputStream(cmsSignedData.getEncoded());
  }

  private static final String PE_01_NOT_SIGNED = "ServiceModelRegUI_no_sign.dll";

  static Stream<Arguments> FakePkiTestProvider() {
    return Stream.of(Arguments.of(PE_01_NOT_SIGNED));
  }
}
