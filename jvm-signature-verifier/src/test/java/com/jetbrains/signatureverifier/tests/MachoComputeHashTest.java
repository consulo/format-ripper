package com.jetbrains.signatureverifier.tests;

import com.jetbrains.signatureverifier.crypt.BcExt;
import com.jetbrains.signatureverifier.macho.MachoArch;
import com.jetbrains.signatureverifier.macho.MachoFile;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

class MachoComputeHashTest {

  @ParameterizedTest
  @MethodSource("MachoComputeHashTestProvider")
  void ComputeHashTest(String machoResourceName, String alg, List<String> expectedResult) throws Exception {
    try (var channel = Files.newByteChannel(TestUtil.getTestDataFile("mach-o", machoResourceName), StandardOpenOption.READ)) {
      Collection<MachoFile> machoFiles = new MachoArch(channel).Extract();
      MachoFile[] filesArray = machoFiles.toArray(new MachoFile[0]);

      for (int index = 0; index < filesArray.length; index++) {
        byte[] result = filesArray[index].ComputeHash(alg);
        Assertions.assertEquals(expectedResult.get(index), BcExt.ConvertToHexString(result).toUpperCase());
      }
    }
  }

  static Stream<Arguments> MachoComputeHashTestProvider() {
    return Stream.of(
      Arguments.of("addhoc",          "SHA1", List.of("B447D37982D38E0B0B275DA5E6869DCA65DBFCD7")),
      Arguments.of("addhoc_resigned", "SHA1", List.of("B447D37982D38E0B0B275DA5E6869DCA65DBFCD7")),
      Arguments.of("notsigned",       "SHA1", List.of("B678215ECF1F02B5E6B2D8F8ACB8DCBC71830102")),
      Arguments.of("nosigned_resigned","SHA1",List.of("B678215ECF1F02B5E6B2D8F8ACB8DCBC71830102")),
      Arguments.of("fat.dylib",       "SHA1", List.of("30D9D3BDF6E0AED26D25218834D930BD9C429808", "F55FF4062F394CBAD57C118CA364EFDD91757CEA")),
      Arguments.of("fat.dylib_signed","SHA1", List.of("30D9D3BDF6E0AED26D25218834D930BD9C429808", "F55FF4062F394CBAD57C118CA364EFDD91757CEA"))
    );
  }
}
