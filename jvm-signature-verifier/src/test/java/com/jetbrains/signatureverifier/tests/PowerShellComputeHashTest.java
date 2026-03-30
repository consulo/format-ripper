package com.jetbrains.signatureverifier.tests;

import com.jetbrains.signatureverifier.crypt.BcExt;
import com.jetbrains.signatureverifier.powershell.PowerShellScriptFile;
import org.apache.commons.io.ByteOrderMark;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.stream.Stream;

class PowerShellComputeHashTest {

  @ParameterizedTest
  @MethodSource("PowerShellComputeHashTestProvider")
  void ComputeHashTest(String resourceName, String expectedResult) throws Exception {
    try (var channel = Files.newByteChannel(TestUtil.getTestDataFile("powershell", resourceName), StandardOpenOption.READ)) {
      PowerShellScriptFile file = new PowerShellScriptFile(channel);
      byte[] result = file.ComputeHash("SHA-256");
      Assertions.assertEquals(expectedResult, BcExt.ConvertToHexString(result).toUpperCase());
    }
  }

  @ParameterizedTest
  @MethodSource("PowerShellContentAndBOM")
  void CheckContentWithoutSignature(String resourceName, String eol, ByteOrderMark bom) throws Exception {
    try (var channel = Files.newByteChannel(TestUtil.getTestDataFile("powershell", resourceName), StandardOpenOption.READ)) {
      PowerShellScriptFile file = new PowerShellScriptFile(channel);
      String content = file.GetContentWithoutSignature();
      if (bom != null) {
        Assertions.assertEquals('\uFEFF', content.charAt(0));
        Assertions.assertEquals(CONTENT.replace("<EOL>", eol), content.substring(1));
      } else {
        Assertions.assertNotEquals((int) '\uFEFF', (int) content.charAt(0));
        Assertions.assertEquals(CONTENT.replace("<EOL>", eol), content);
      }
    }
  }

  static final String CONTENT =
    "Write-Host \"PSExecutionPolicyPreference is '$($env:PSExecutionPolicyPreference)'\"<EOL>" +
    "Write-Host \"Some Unicode characters just to check encoding: \u042e\u043d\u0438\u043a\u043e\u0434 \ua66e\uD83C\uDCA1\uD83D\uDE0E\"";

  static Stream<Arguments> PowerShellComputeHashTestProvider() {
    String hashLF         = "8F47E600DC6399B506C1F8F1E57F98026FDF9EA119FF19BDE92EDD670EE8E46D";
    String hashCRLF       = "26281693B5A646B765591BE3A47D3DDBD99B76B91BAA1760ED6A069C9C877C97";
    String hashLF_no_BOM  = "1D5B22A7CC0752D27D6A460BD38AC5B255E48B679D0149510CD63003DCA29B2C";
    String hashCRLF_no_BOM= "8A441A48D8922E06288C9D1C495DA2C399B00CDA5350163287F1DB6A9265B0D7";

    return Stream.of(
      Arguments.of("script-utf-8-no-bom-crlf.ps1",   hashCRLF_no_BOM),
      Arguments.of("script-utf-8-no-bom-lf.ps1",     hashLF_no_BOM),
      Arguments.of("script-utf-8-bom-crlf.ps1",      hashCRLF),
      Arguments.of("script-utf-8-bom-lf.ps1",        hashLF),
      Arguments.of("script-utf-16be-crlf.ps1",       hashCRLF),
      Arguments.of("script-utf-16be-lf.ps1",         hashLF),
      Arguments.of("script-utf-16le-crlf.ps1",       hashCRLF),
      Arguments.of("script-utf-16le-lf.ps1",         hashLF),
      Arguments.of("signed-script-utf-8-no-bom-crlf.ps1",  hashCRLF_no_BOM),
      Arguments.of("signed-script-utf-8-no-bom-lf.ps1",    hashLF_no_BOM),
      Arguments.of("signed-script-utf-8-bom-crlf.ps1",     hashCRLF),
      Arguments.of("signed-script-utf-8-bom-lf.ps1",       hashLF),
      Arguments.of("signed-script-utf-16be-crlf.ps1",      hashCRLF),
      Arguments.of("signed-script-utf-16be-lf.ps1",        hashLF),
      Arguments.of("signed-script-utf-16le-crlf.ps1",      hashCRLF),
      Arguments.of("signed-script-utf-16le-lf.ps1",        hashLF)
    );
  }

  static Stream<Arguments> PowerShellContentAndBOM() {
    String CRLF = "\r\n";
    String LF   = "\n";
    return Stream.of(
      Arguments.of("script-utf-8-no-bom-crlf.ps1", CRLF, null),
      Arguments.of("script-utf-8-no-bom-lf.ps1",   LF,   null),
      Arguments.of("script-utf-8-bom-crlf.ps1",    CRLF, ByteOrderMark.UTF_8),
      Arguments.of("script-utf-8-bom-lf.ps1",      LF,   ByteOrderMark.UTF_8),
      Arguments.of("script-utf-16be-crlf.ps1",     CRLF, ByteOrderMark.UTF_16BE),
      Arguments.of("script-utf-16be-lf.ps1",       LF,   ByteOrderMark.UTF_16BE),
      Arguments.of("script-utf-16le-crlf.ps1",     CRLF, ByteOrderMark.UTF_16LE),
      Arguments.of("script-utf-16le-lf.ps1",       LF,   ByteOrderMark.UTF_16LE),
      Arguments.of("signed-script-utf-8-no-bom-crlf.ps1", CRLF, null),
      Arguments.of("signed-script-utf-8-no-bom-lf.ps1",   LF,   null),
      Arguments.of("signed-script-utf-8-bom-crlf.ps1",    CRLF, ByteOrderMark.UTF_8),
      Arguments.of("signed-script-utf-8-bom-lf.ps1",      LF,   ByteOrderMark.UTF_8),
      Arguments.of("signed-script-utf-16be-crlf.ps1",     CRLF, ByteOrderMark.UTF_16BE),
      Arguments.of("signed-script-utf-16be-lf.ps1",       LF,   ByteOrderMark.UTF_16BE),
      Arguments.of("signed-script-utf-16le-crlf.ps1",     CRLF, ByteOrderMark.UTF_16LE),
      Arguments.of("signed-script-utf-16le-lf.ps1",       LF,   ByteOrderMark.UTF_16LE)
    );
  }
}
