package com.jetbrains.util.filetype.tests;

import com.jetbrains.util.filetype.TestUtil;
import com.jetbrains.util.filetype.FileProperties;
import com.jetbrains.util.filetype.FileType;
import com.jetbrains.util.filetype.FileTypeDetector;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.channels.SeekableByteChannel;
import java.util.AbstractMap;
import java.util.EnumSet;
import java.util.stream.Stream;

class FileTypeDetectorTest {

  @ParameterizedTest
  @MethodSource("DetectFileTypeTestProvider")
  void DetectFileTypeTest(String filename, FileType expectedFileType,
                          EnumSet<FileProperties> expectedFileProperties) throws Exception {
    AbstractMap.SimpleImmutableEntry<FileType, EnumSet<FileProperties>> result;
    try (SeekableByteChannel channel = TestUtil.getTestByteChannel(filename)) {
      result = FileTypeDetector.detectFileType(channel);
    }

    Assertions.assertEquals(expectedFileType, result.getKey());
    Assertions.assertEquals(expectedFileProperties, result.getValue());
  }

  static Stream<Arguments> DetectFileTypeTestProvider() {
    return Stream.of(
      Arguments.of("error0", FileType.Unknown, e(FileProperties.UnknownType)),
      Arguments.of("error4", FileType.Unknown, e(FileProperties.UnknownType)),
      Arguments.of("error_mach-o", FileType.Unknown, e(FileProperties.UnknownType)),
      Arguments.of("error_msi", FileType.Unknown, e(FileProperties.UnknownType)),
      Arguments.of("error_pe", FileType.Unknown, e(FileProperties.UnknownType)),
      Arguments.of("wscadminui.x64.exe", FileType.Pe, e(FileProperties.ExecutableType)),
      Arguments.of("wscadminui.x86.exe", FileType.Pe, e(FileProperties.ExecutableType)),
      Arguments.of("winrsmgr.x64.dll", FileType.Pe, e(FileProperties.SharedLibraryType)),
      Arguments.of("winrsmgr.x86.dll", FileType.Pe, e(FileProperties.SharedLibraryType)),
      Arguments.of("2dac4b.msi", FileType.Msi, e(FileProperties.UnknownType)),
      Arguments.of("env-wrapper.x64", FileType.MachO, e(FileProperties.ExecutableType, FileProperties.Signed)),
      Arguments.of("libMonoSupportW.x64.dylib", FileType.MachO, e(FileProperties.SharedLibraryType, FileProperties.Signed)),
      Arguments.of("fat.dylib", FileType.MachO, e(FileProperties.SharedLibraryType, FileProperties.MultiArch)),
      Arguments.of("x64.dylib", FileType.MachO, e(FileProperties.SharedLibraryType)),
      Arguments.of("x86.dylib", FileType.MachO, e(FileProperties.SharedLibraryType)),
      Arguments.of("fat.bundle", FileType.MachO, e(FileProperties.BundleType, FileProperties.MultiArch)),
      Arguments.of("x64.bundle", FileType.MachO, e(FileProperties.BundleType)),
      Arguments.of("x86.bundle", FileType.MachO, e(FileProperties.BundleType)),
      Arguments.of("cat", FileType.MachO, e(FileProperties.ExecutableType, FileProperties.MultiArch, FileProperties.Signed)),
      Arguments.of("fsnotifier", FileType.MachO, e(FileProperties.ExecutableType, FileProperties.MultiArch)),
      Arguments.of("tempfile.x64", FileType.Elf, e(FileProperties.ExecutableType)),
      Arguments.of("libulockmgr.so.1.0.1.x64", FileType.Elf, e(FileProperties.SharedLibraryType)),
      Arguments.of("catsay.ppc64", FileType.Elf, e(FileProperties.ExecutableType)),
      Arguments.of("catsay.x86", FileType.Elf, e(FileProperties.ExecutableType)),
      Arguments.of("vl805", FileType.Elf, e(FileProperties.ExecutableType)),
      Arguments.of("libpcprofile.so", FileType.Elf, e(FileProperties.SharedLibraryType)),
      Arguments.of("System.Security.Principal.Windows.dll", FileType.Pe,
        e(FileProperties.SharedLibraryType, FileProperties.Managed, FileProperties.Signed)),
      Arguments.of("api-ms-win-core-rtlsupport-l1-1-0.dll", FileType.Pe,
        e(FileProperties.SharedLibraryType, FileProperties.Signed)),
      Arguments.of("Armature.Interface.dll", FileType.Pe,
        e(FileProperties.SharedLibraryType, FileProperties.Managed)),
      Arguments.of("1.sh", FileType.ShebangScript, e(FileProperties.ExecutableType)),
      Arguments.of("2.sh", FileType.ShebangScript, e(FileProperties.ExecutableType))
    );
  }

  @SafeVarargs
  private static <T extends Enum<T>> EnumSet<T> e(T... items) {
    return TestUtil.enumSetOf(items);
  }
}
