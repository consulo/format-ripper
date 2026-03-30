package com.jetbrains.signatureverifier.tests;

import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams;
import com.jetbrains.signatureverifier.crypt.SignedMessage;
import com.jetbrains.signatureverifier.crypt.SignedMessageVerifier;
import com.jetbrains.signatureverifier.crypt.VerifySignatureResult;
import com.jetbrains.signatureverifier.crypt.VerifySignatureStatus;
import com.jetbrains.signatureverifier.powershell.PowerShellScriptFile;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.InputStream;
import java.nio.channels.SeekableByteChannel;
import java.util.stream.Stream;

class PowerShellSignatureVerifierTests {
  private final SignatureVerificationParams simpleVerificationParams =
    new SignatureVerificationParams(null, null, false, false);

  @ParameterizedTest
  @MethodSource("VerifySignTestProvider")
  void VerifySignTest(String resourceName, VerifySignatureStatus expectedResult) throws Exception {
    VerifySignatureResult result = verifySign(resourceName);
    if (expectedResult != result.getStatus()) {
      Assertions.fail("Expected status: " + expectedResult + ", but got: " + result.getStatus() + ", message: " + result.getMessage());
    }
  }

  @ParameterizedTest
  @MethodSource("VerifySignWithChainTestProvider")
  void VerifySignWithChainTest(String resourceName, VerifySignatureStatus expectedResult) throws Exception {
    VerifySignatureResult result = verifySignWithChain(resourceName);
    if (expectedResult != result.getStatus()) {
      Assertions.fail("Expected status: " + expectedResult + ", but got: " + result.getStatus() + ", message: " + result.getMessage());
    }
  }

  private VerifySignatureResult verifySign(String resourceName) throws Exception {
    try (SeekableByteChannel channel = TestUtil.getTestByteChannel("powershell", resourceName)) {
      PowerShellScriptFile psFile = new PowerShellScriptFile(channel);
      var signatureData = psFile.getSignatureData();
      if (signatureData.isEmpty()) {
        return new VerifySignatureResult(VerifySignatureStatus.InvalidSignature, "Cannot extract signature from file");
      }
      SignedMessage signedMessage = SignedMessage.createInstance(signatureData);
      VerifySignatureResult result = psFile.verifyContentHash(signedMessage.SignedData, psFile);
      if (result.isNotValid()) {
        return result;
      }
      SignedMessageVerifier signedMessageVerifier = new SignedMessageVerifier();
      return signedMessageVerifier.verifySignatureAsync(signedMessage, simpleVerificationParams);
    }
  }

  private VerifySignatureResult verifySignWithChain(String resourceName) throws Exception {
    try (InputStream is = TestUtil.getTestDataInputStream("powershell", resourceName)) {
      PowerShellScriptFile file = new PowerShellScriptFile(is);
      var signatureData = file.getSignatureData();
      if (signatureData.isEmpty()) {
        return new VerifySignatureResult(VerifySignatureStatus.InvalidSignature, "Cannot extract signature from file");
      }
      SignedMessage signedMessage = SignedMessage.createInstance(signatureData);
      SignedMessageVerifier signedMessageVerifier = new SignedMessageVerifier();
      return signedMessageVerifier.verifySignatureAsync(signedMessage, getChainVerificationParams());
    }
  }

  private boolean chainParamsComputed = false;
  private SignatureVerificationParams chainVerificationParams;

  private SignatureVerificationParams getChainVerificationParams() throws Exception {
    if (!chainParamsComputed) {
      try (InputStream codesignroots = TestUtil.getTestDataInputStream("powershell", DIGICERT_ROOT_G4);
           InputStream timestamproots = TestUtil.getTestDataInputStream("powershell", DIGICERT_ROOT_G4)) {
        SignatureVerificationParams params = new SignatureVerificationParams(codesignroots, timestamproots, true, false);
        params.getRootCertificates(); // fully read streams
        chainVerificationParams = params;
      }
      chainParamsComputed = true;
    }
    return chainVerificationParams;
  }

  private static final String DIGICERT_ROOT_G4 = "DigiCertTrustedRootG4.crt.pem";

  static Stream<Arguments> VerifySignTestProvider() {
    return Stream.of(
      // unsigned
      Arguments.of("script-utf-8-no-bom-crlf.ps1",  VerifySignatureStatus.InvalidSignature),
      Arguments.of("script-utf-8-no-bom-lf.ps1",    VerifySignatureStatus.InvalidSignature),
      Arguments.of("script-utf-8-bom-crlf.ps1",     VerifySignatureStatus.InvalidSignature),
      Arguments.of("script-utf-8-bom-lf.ps1",       VerifySignatureStatus.InvalidSignature),
      Arguments.of("script-utf-16be-crlf.ps1",      VerifySignatureStatus.InvalidSignature),
      Arguments.of("script-utf-16be-lf.ps1",        VerifySignatureStatus.InvalidSignature),
      Arguments.of("script-utf-16le-crlf.ps1",      VerifySignatureStatus.InvalidSignature),
      Arguments.of("script-utf-16le-lf.ps1",        VerifySignatureStatus.InvalidSignature),
      // signed
      Arguments.of("signed-script-utf-8-no-bom-crlf.ps1",  VerifySignatureStatus.Valid),
      Arguments.of("signed-script-utf-8-no-bom-lf.ps1",    VerifySignatureStatus.Valid),
      Arguments.of("signed-script-utf-8-bom-crlf.ps1",     VerifySignatureStatus.Valid),
      Arguments.of("signed-script-utf-8-bom-lf.ps1",       VerifySignatureStatus.Valid),
      Arguments.of("signed-script-utf-16be-crlf.ps1",      VerifySignatureStatus.Valid),
      Arguments.of("signed-script-utf-16be-lf.ps1",        VerifySignatureStatus.Valid),
      Arguments.of("signed-script-utf-16le-crlf.ps1",      VerifySignatureStatus.Valid),
      Arguments.of("signed-script-utf-16le-lf.ps1",        VerifySignatureStatus.Valid),
      // signed and then edited
      Arguments.of("corrupted-script-utf-16le-crlf.ps1", VerifySignatureStatus.InvalidSignature)
    );
  }

  static Stream<Arguments> VerifySignWithChainTestProvider() {
    return Stream.of(
      // unsigned
      Arguments.of("script-utf-8-no-bom-crlf.ps1",  VerifySignatureStatus.InvalidSignature),
      Arguments.of("script-utf-8-no-bom-lf.ps1",    VerifySignatureStatus.InvalidSignature),
      Arguments.of("script-utf-8-bom-crlf.ps1",     VerifySignatureStatus.InvalidSignature),
      Arguments.of("script-utf-8-bom-lf.ps1",       VerifySignatureStatus.InvalidSignature),
      Arguments.of("script-utf-16be-crlf.ps1",      VerifySignatureStatus.InvalidSignature),
      Arguments.of("script-utf-16be-lf.ps1",        VerifySignatureStatus.InvalidSignature),
      Arguments.of("script-utf-16le-crlf.ps1",      VerifySignatureStatus.InvalidSignature),
      Arguments.of("script-utf-16le-lf.ps1",        VerifySignatureStatus.InvalidSignature),
      // signed
      Arguments.of("signed-script-utf-8-no-bom-crlf.ps1",  VerifySignatureStatus.Valid),
      Arguments.of("signed-script-utf-8-no-bom-lf.ps1",    VerifySignatureStatus.Valid),
      Arguments.of("signed-script-utf-8-bom-crlf.ps1",     VerifySignatureStatus.Valid),
      Arguments.of("signed-script-utf-8-bom-lf.ps1",       VerifySignatureStatus.Valid),
      Arguments.of("signed-script-utf-16be-crlf.ps1",      VerifySignatureStatus.Valid),
      Arguments.of("signed-script-utf-16be-lf.ps1",        VerifySignatureStatus.Valid),
      Arguments.of("signed-script-utf-16le-crlf.ps1",      VerifySignatureStatus.Valid),
      Arguments.of("signed-script-utf-16le-lf.ps1",        VerifySignatureStatus.Valid)
    );
  }
}
