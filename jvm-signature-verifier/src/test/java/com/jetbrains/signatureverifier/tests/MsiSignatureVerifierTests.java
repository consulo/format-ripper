package com.jetbrains.signatureverifier.tests;

import com.jetbrains.signatureverifier.cf.MsiFile;
import com.jetbrains.signatureverifier.crypt.BcExt;
import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams;
import com.jetbrains.signatureverifier.crypt.SignedMessage;
import com.jetbrains.signatureverifier.crypt.SignedMessageVerifier;
import com.jetbrains.signatureverifier.crypt.VerifySignatureStatus;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

class MsiSignatureVerifierTests {

  @ParameterizedTest
  @MethodSource("VerifySignTestProvider")
  void VerifySignTest(String resourceName, VerifySignatureStatus expectedResult) throws Exception {
    try (var channel = TestUtil.getTestByteChannel("msi", resourceName)) {
      SignatureVerificationParams verificationParams = new SignatureVerificationParams(null, null, false, false);
      MsiFile msiFile = new MsiFile(channel);
      var signatureData = msiFile.getSignatureData();
      var signedMessage = SignedMessage.createInstance(signatureData);
      SignedMessageVerifier signedMessageVerifier = new SignedMessageVerifier();
      var result = signedMessageVerifier.verifySignatureAsync(signedMessage, verificationParams);
      Assertions.assertEquals(expectedResult, result.getStatus());
    }
  }

  @ParameterizedTest
  @MethodSource("ComputeHashTestProvider")
  void ComputeHashTest(String resourceName, String alg, String expectedResult) throws Exception {
    try (var channel = TestUtil.getTestByteChannel("msi", resourceName)) {
      MsiFile msiFile = new MsiFile(channel);
      byte[] result = msiFile.ComputeHash(alg, true);
      Assertions.assertEquals(expectedResult, BcExt.convertToHexString(result).toUpperCase());
    }
  }

  static Stream<Arguments> VerifySignTestProvider() {
    return Stream.of(
      Arguments.of(MSI_01_SIGNED,          VerifySignatureStatus.Valid),
      Arguments.of(MSI_01_BROKEN_HASH,     VerifySignatureStatus.InvalidSignature),
      Arguments.of(MSI_01_BROKEN_SIGN,     VerifySignatureStatus.InvalidSignature),
      Arguments.of(MSI_01_BROKEN_TIMESTAMP,VerifySignatureStatus.InvalidSignature)
    );
  }

  static Stream<Arguments> ComputeHashTestProvider() {
    return Stream.of(
      Arguments.of(MSI_01_SIGNED,     "SHA1", MSI_01_SHA1),
      Arguments.of(MSI_01_NOT_SIGNED, "SHA1", MSI_01_SHA1)
    );
  }

  private static final String MSI_01_SIGNED            = "2dac4b.msi";
  private static final String MSI_01_NOT_SIGNED        = "2dac4b_not_signed.msi";
  private static final String MSI_01_BROKEN_HASH       = "2dac4b_broken_hash.msi";
  private static final String MSI_01_BROKEN_SIGN       = "2dac4b_broken_sign.msi";
  private static final String MSI_01_BROKEN_TIMESTAMP  = "2dac4b_broken_timestamp.msi";
  private static final String MSI_01_SHA1              = "CBBE5C1017C8A65FFEB9219F465C949563A0E256";
}
