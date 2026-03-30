package com.jetbrains.signatureverifier.tests;

import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams;
import com.jetbrains.signatureverifier.crypt.SignedMessage;
import com.jetbrains.signatureverifier.crypt.SignedMessageVerifier;
import com.jetbrains.signatureverifier.crypt.VerifySignatureStatus;
import com.jetbrains.signatureverifier.macho.MachoArch;
import com.jetbrains.signatureverifier.macho.MachoFile;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.InputStream;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

class MachoSignatureVerifierTests {

  @ParameterizedTest
  @MethodSource("VerifySignTestProvider")
  void VerifySignTest(String machoResourceName, VerifySignatureStatus expectedResult) throws Exception {
    try (var channel = Files.newByteChannel(TestUtil.getTestDataFile("mach-o", machoResourceName), StandardOpenOption.READ)) {
      Collection<MachoFile> machoFiles = new MachoArch(channel).extract();
      SignatureVerificationParams verificationParams = new SignatureVerificationParams(null, null, false, false);
      SignedMessageVerifier signedMessageVerifier = new SignedMessageVerifier();

      for (MachoFile machoFile : machoFiles) {
        var signatureData = machoFile.getSignatureData();
        var signedMessage = SignedMessage.createInstance(signatureData);
        var result = signedMessageVerifier.verifySignatureAsync(signedMessage, verificationParams);
        Assertions.assertEquals(expectedResult, result.getStatus());
      }
    }
  }

  @ParameterizedTest
  @MethodSource("VerifySignInvalidSignatureFormatTestProvider")
  void VerifySignInvalidSignatureFormat(String machoResourceName) throws Exception {
    try (var channel = Files.newByteChannel(TestUtil.getTestDataFile("mach-o", machoResourceName), StandardOpenOption.READ)) {
      Collection<MachoFile> machoFiles = new MachoArch(channel).extract();
      for (MachoFile machoFile : machoFiles) {
        var signatureData = machoFile.getSignatureData();
        Exception thrown = Assertions.assertThrows(Exception.class, () -> SignedMessage.createInstance(signatureData));
        Assertions.assertTrue(thrown.getMessage().contains("Invalid signature format"));
      }
    }
  }

  @ParameterizedTest
  @MethodSource("VerifySignWithChainTestProvider")
  void VerifySignWithChainTest(String machOResourceName, VerifySignatureStatus expectedResult,
                               String codesignRootCertStoreResourceName) throws Exception {
    try (InputStream codesignroots = TestUtil.getTestDataInputStream("mach-o", codesignRootCertStoreResourceName)) {
      SignatureVerificationParams verificationParams = new SignatureVerificationParams(codesignroots, null, true, false);

      List<VerifySignatureStatus> results = new ArrayList<>();
      try (SeekableByteChannel machOFileStream = TestUtil.getTestByteChannel("mach-o", machOResourceName)) {
        Collection<MachoFile> machoFiles = new MachoArch(machOFileStream).extract();
        SignedMessageVerifier signedMessageVerifier = new SignedMessageVerifier();

        for (MachoFile machoFile : machoFiles) {
          var signatureData = machoFile.getSignatureData();
          var signedMessage = SignedMessage.createInstance(signatureData);
          results.add(signedMessageVerifier.verifySignatureAsync(signedMessage, verificationParams).getStatus());
        }
      }

      for (VerifySignatureStatus status : results) {
        Assertions.assertEquals(expectedResult, status);
      }
    }
  }

  static Stream<Arguments> VerifySignTestProvider() {
    return Stream.of(
      Arguments.of("env-wrapper.x64",                VerifySignatureStatus.Valid),
      Arguments.of("libMonoSupportW.x64.dylib",       VerifySignatureStatus.Valid),
      Arguments.of("cat",                             VerifySignatureStatus.Valid),
      Arguments.of("JetBrains.Profiler.PdbServer",    VerifySignatureStatus.Valid),
      Arguments.of("fat.dylib_signed",                VerifySignatureStatus.Valid),
      Arguments.of("libhostfxr.dylib",                VerifySignatureStatus.Valid)
    );
  }

  static Stream<Arguments> VerifySignInvalidSignatureFormatTestProvider() {
    return Stream.of(
      Arguments.of("libSystem.Net.Security.Native.dylib")
    );
  }

  static Stream<Arguments> VerifySignWithChainTestProvider() {
    return Stream.of(
      Arguments.of("JetBrains.Profiler.PdbServer",  VerifySignatureStatus.Valid, "apple_root.p7b"),
      Arguments.of("cat",                           VerifySignatureStatus.Valid, "apple_root.p7b"),
      Arguments.of("env-wrapper.x64",               VerifySignatureStatus.Valid, "apple_root.p7b"),
      Arguments.of("libMonoSupportW.x64.dylib",     VerifySignatureStatus.Valid, "apple_root.p7b"),
      Arguments.of("libhostfxr.dylib",              VerifySignatureStatus.Valid, "apple_root.p7b")
    );
  }
}
