package com.jetbrains.signatureverifier.tests;

import com.jetbrains.signatureverifier.PeFile;
import com.jetbrains.signatureverifier.crypt.BcExt;
import com.jetbrains.signatureverifier.crypt.SignatureValidationTimeMode;
import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams;
import com.jetbrains.signatureverifier.crypt.SignedMessage;
import com.jetbrains.signatureverifier.crypt.SignedMessageVerifier;
import com.jetbrains.signatureverifier.crypt.Utils;
import com.jetbrains.signatureverifier.crypt.VerifySignatureResult;
import com.jetbrains.signatureverifier.crypt.VerifySignatureStatus;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.InputStream;
import java.nio.channels.SeekableByteChannel;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.stream.Stream;

class PeSignatureVerifierTests {

  @ParameterizedTest
  @MethodSource("VerifySignTestProvider")
  void VerifySignTest(String peResourceName, VerifySignatureStatus expectedResult) throws Exception {
    try (SeekableByteChannel channel = TestUtil.getTestByteChannel("pe", peResourceName)) {
      SignatureVerificationParams verificationParams = new SignatureVerificationParams(null, null, false, false);
      PeFile peFile = new PeFile(channel);
      var signatureData = peFile.GetSignatureData();
      var signedMessage = SignedMessage.CreateInstance(signatureData);
      SignedMessageVerifier signedMessageVerifier = new SignedMessageVerifier();
      var result = signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
      Assertions.assertEquals(expectedResult, result.Status());
    }
  }

  @ParameterizedTest
  @MethodSource("VerifySignWithChainTestProvider")
  void VerifySignWithChainTest(String peResourceName, VerifySignatureStatus expectedResult,
                               String codesignRootCertStoreResourceName,
                               String timestampRootCertStoreResourceName) throws Exception {
    try (SeekableByteChannel peFileStream = TestUtil.getTestByteChannel("pe", peResourceName);
         InputStream codesignroots = TestUtil.getTestDataInputStream("pe", codesignRootCertStoreResourceName);
         InputStream timestamproots = TestUtil.getTestDataInputStream("pe", timestampRootCertStoreResourceName)) {
      SignatureVerificationParams verificationParams = new SignatureVerificationParams(
        codesignroots, timestamproots, true, false
      );
      PeFile peFile = new PeFile(peFileStream);
      var signatureData = peFile.GetSignatureData();
      var signedMessage = SignedMessage.CreateInstance(signatureData);
      SignedMessageVerifier signedMessageVerifier = new SignedMessageVerifier();
      var result = signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
      Assertions.assertEquals(expectedResult, result.Status());
    }
  }

  @ParameterizedTest
  @MethodSource("VerifySignWithChainTestInPastProvider")
  void VerifySignWithChainTestInPast(String peResourceName, VerifySignatureStatus expectedResult,
                                     String codesignRoot, String timestampRoot) throws Exception {
    VerifySignatureResult actual = verifySignWithChainInTime(
      peResourceName, codesignRoot, timestampRoot, Utils.ConvertToLocalDateTime(new Date(Long.MIN_VALUE))
    );
    Assertions.assertEquals(expectedResult, actual.Status());
  }

  @ParameterizedTest
  @MethodSource("VerifySignWithChainTestInPresentProvider")
  void VerifySignWithChainTestInPresent(String peResourceName, VerifySignatureStatus expectedResult,
                                        String codesignRoot, String timestampRoot) throws Exception {
    VerifySignatureResult actual = verifySignWithChainInTime(
      peResourceName, codesignRoot, timestampRoot, LocalDateTime.now()
    );
    Assertions.assertEquals(expectedResult, actual.Status());
  }

  @ParameterizedTest
  @MethodSource("VerifySignWithChainTestInFutureProvider")
  void VerifySignWithChainTestInFuture(String peResourceName, VerifySignatureStatus expectedResult,
                                       String codesignRoot, String timestampRoot) throws Exception {
    VerifySignatureResult actual = verifySignWithChainInTime(
      peResourceName, codesignRoot, timestampRoot, Utils.ConvertToLocalDateTime(new Date(Long.MAX_VALUE))
    );
    Assertions.assertEquals(expectedResult, actual.Status());
  }

  @ParameterizedTest
  @MethodSource("VerifySignWithChainTestAboutSignTimeProvider")
  void VerifySignWithChainTestAboutSignTime(String peResourceName, VerifySignatureStatus expectedResult,
                                            String codesignRoot, String timestampRoot) throws Exception {
    VerifySignatureResult actual = verifySignWithChainInTime(
      peResourceName, codesignRoot, timestampRoot, LocalDateTime.of(2019, 11, 24, 0, 0)
    );
    Assertions.assertEquals(expectedResult, actual.Status());
  }

  private VerifySignatureResult verifySignWithChainInTime(String peResourceName,
                                                          String codesignRootCertStoreResourceName,
                                                          String timestampRootCertStoreResourceName,
                                                          LocalDateTime time) throws Exception {
    try (SeekableByteChannel peFileStream = TestUtil.getTestByteChannel("pe", peResourceName);
         InputStream codesignroots = TestUtil.getTestDataInputStream("pe", codesignRootCertStoreResourceName);
         InputStream timestamproots = TestUtil.getTestDataInputStream("pe", timestampRootCertStoreResourceName)) {
      SignatureVerificationParams verificationParams = new SignatureVerificationParams(
        codesignroots, timestamproots, true, false, null,
        SignatureValidationTimeMode.SignValidationTime, time
      );
      PeFile peFile = new PeFile(peFileStream);
      var signatureData = peFile.GetSignatureData();
      var signedMessage = SignedMessage.CreateInstance(signatureData);
      SignedMessageVerifier signedMessageVerifier = new SignedMessageVerifier();
      return signedMessageVerifier.VerifySignatureAsync(signedMessage, verificationParams);
    }
  }

  @ParameterizedTest
  @MethodSource("ComputeHashTestProvider")
  void ComputeHashTest(String peResourceName, String alg, String expectedResult) throws Exception {
    try (SeekableByteChannel channel = TestUtil.getTestByteChannel("pe", peResourceName)) {
      PeFile peFile = new PeFile(channel);
      byte[] result = peFile.ComputeHash(alg);
      Assertions.assertEquals(expectedResult, BcExt.ConvertToHexString(result).toUpperCase());
    }
  }

  @ParameterizedTest
  @MethodSource("VerifyIsDotNetProvider")
  void IsDotNetTest(String peResourceName, boolean expectedResult) throws Exception {
    try (SeekableByteChannel channel = TestUtil.getTestByteChannel("pe", peResourceName)) {
      PeFile peFile = new PeFile(channel);
      Assertions.assertEquals(expectedResult, peFile.IsDotNet());
    }
  }

  private static final String PE_01_SIGNED            = "ServiceModelRegUI.dll";
  private static final String PE_01_NOT_SIGNED        = "ServiceModelRegUI_no_sign.dll";
  private static final String PE_01_TRIMMED_SIGN      = "ServiceModelRegUI_trimmed_sign.dll";
  private static final String PE_01_EMPTY_SIGN        = "ServiceModelRegUI_empty_sign.dll";
  private static final String PE_01_BROKEN_HASH       = "ServiceModelRegUI_broken_hash.dll";
  private static final String PE_01_SHA1              = "D64EC6AEC642441554E7CBA0E0513E35683C87AE";
  private static final String PE_01_BROKEN_SIGN       = "ServiceModelRegUI_broken_sign.dll";
  private static final String PE_01_BROKEN_COUNTER_SIGN        = "ServiceModelRegUI_broken_counter_sign.dll";
  private static final String PE_01_BROKEN_NESTED_SIGN         = "ServiceModelRegUI_broken_nested_sign.dll";
  private static final String PE_01_BROKEN_NESTED_SIGN_TIMESTAMP = "ServiceModelRegUI_broken_nested_sign_timestamp.dll";
  private static final String PE_01_SHA256            = "834394AC48C8AB8F6D21E64A2461BA196D28140558D36430C057E49ADF41967A";
  private static final String MS_CODESIGN_ROOTS       = "ms_codesign_roots.p7b";
  private static final String MS_TIMESTAMP_ROOT       = "ms_timestamp_root.p7b";
  private static final String PE_02_EMPTY_SIGN        = "uninst.exe";
  private static final String PE_02_SHA1              = "58AA2C6CF6A446426F3596F1BC4AB4E1FAAC297A";
  private static final String PE_03_SIGNED            = "shell32.dll";
  private static final String PE_03_SHA256            = "BB79CC7089BF061ED707FFB3FFA4ADE1DDAED0396878CC92D54A0E20A3C81619";
  private static final String PE_04_SIGNED            = "IntelAudioService.exe";
  private static final String PE_04_SHA256            = "160F2FE667A9252AB5B2E01749CD40B024E749B10B49AD276345875BA073A57E";
  private static final String PE_05_SIGNED            = "libcrypto-1_1-x64.dll";
  private static final String PE_06_SIGNED            = "libssl-1_1-x64.dll";
  private static final String PE_07_SIGNED            = "JetBrains.dotUltimate.2021.3.EAP1D.Checked.web.exe";
  private static final String JB_CODESIGN_ROOTS       = "jb_codesign_roots.p7b";
  private static final String JB_TIMESTAMP_ROOTS      = "jb_timestamp_roots.p7b";
  private static final String PE_08_SIGNED            = "dotnet.exe";
  private static final String PE_09_BROKEN_TIMESTAMP  = "dotnet_broken_timestamp.exe";

  static Stream<Arguments> ComputeHashTestProvider() {
    return Stream.of(
      Arguments.of(PE_01_SIGNED,     "SHA-1",   PE_01_SHA1),
      Arguments.of(PE_01_NOT_SIGNED, "SHA-1",   PE_01_SHA1),
      Arguments.of(PE_01_SIGNED,     "SHA-256",  PE_01_SHA256),
      Arguments.of(PE_01_NOT_SIGNED, "SHA-256",  PE_01_SHA256),
      Arguments.of(PE_01_TRIMMED_SIGN,"SHA-1",  PE_01_SHA1),
      Arguments.of(PE_01_EMPTY_SIGN,  "SHA-1",  PE_01_SHA1),
      Arguments.of(PE_02_EMPTY_SIGN,  "SHA-1",  PE_02_SHA1),
      Arguments.of(PE_03_SIGNED,      "SHA-256", PE_03_SHA256),
      Arguments.of(PE_04_SIGNED,      "SHA-256", PE_04_SHA256)
    );
  }

  static Stream<Arguments> VerifySignTestProvider() {
    return Stream.of(
      Arguments.of(PE_01_SIGNED,                       VerifySignatureStatus.Valid),
      Arguments.of(PE_01_BROKEN_HASH,                  VerifySignatureStatus.InvalidSignature),
      Arguments.of(PE_01_BROKEN_SIGN,                  VerifySignatureStatus.InvalidSignature),
      Arguments.of(PE_01_BROKEN_COUNTER_SIGN,          VerifySignatureStatus.InvalidSignature),
      Arguments.of(PE_01_BROKEN_NESTED_SIGN,           VerifySignatureStatus.InvalidSignature),
      Arguments.of(PE_01_BROKEN_NESTED_SIGN_TIMESTAMP, VerifySignatureStatus.InvalidTimestamp),
      Arguments.of(PE_03_SIGNED,                       VerifySignatureStatus.Valid),
      Arguments.of(PE_04_SIGNED,                       VerifySignatureStatus.Valid),
      Arguments.of(PE_05_SIGNED,                       VerifySignatureStatus.InvalidSignature),
      Arguments.of(PE_06_SIGNED,                       VerifySignatureStatus.InvalidSignature),
      Arguments.of(PE_07_SIGNED,                       VerifySignatureStatus.Valid),
      Arguments.of(PE_09_BROKEN_TIMESTAMP,             VerifySignatureStatus.InvalidTimestamp)
    );
  }

  static Stream<Arguments> VerifySignWithChainTestProvider() {
    return Stream.of(
      Arguments.of(PE_01_SIGNED, VerifySignatureStatus.Valid, MS_CODESIGN_ROOTS, MS_TIMESTAMP_ROOT),
      Arguments.of(PE_07_SIGNED, VerifySignatureStatus.Valid, JB_CODESIGN_ROOTS, JB_TIMESTAMP_ROOTS),
      Arguments.of(PE_08_SIGNED, VerifySignatureStatus.Valid, MS_CODESIGN_ROOTS, MS_TIMESTAMP_ROOT)
    );
  }

  static Stream<Arguments> VerifySignWithChainTestInPastProvider() {
    return Stream.of(Arguments.of(PE_01_SIGNED, VerifySignatureStatus.InvalidChain, MS_CODESIGN_ROOTS, MS_TIMESTAMP_ROOT));
  }

  static Stream<Arguments> VerifySignWithChainTestInPresentProvider() {
    return Stream.of(Arguments.of(PE_01_SIGNED, VerifySignatureStatus.InvalidChain, MS_CODESIGN_ROOTS, MS_TIMESTAMP_ROOT));
  }

  static Stream<Arguments> VerifySignWithChainTestInFutureProvider() {
    return Stream.of(Arguments.of(PE_01_SIGNED, VerifySignatureStatus.InvalidChain, MS_CODESIGN_ROOTS, MS_TIMESTAMP_ROOT));
  }

  static Stream<Arguments> VerifySignWithChainTestAboutSignTimeProvider() {
    return Stream.of(Arguments.of(PE_01_SIGNED, VerifySignatureStatus.Valid, MS_CODESIGN_ROOTS, MS_TIMESTAMP_ROOT));
  }

  static Stream<Arguments> VerifyIsDotNetProvider() {
    return Stream.of(
      Arguments.of(PE_01_SIGNED, false),
      Arguments.of(PE_04_SIGNED, true)
    );
  }
}
