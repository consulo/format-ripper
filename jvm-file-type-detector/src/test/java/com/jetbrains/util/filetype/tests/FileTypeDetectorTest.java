package com.jetbrains.util.filetype.tests;

import com.jetbrains.util.filetype.TestUtil;
import com.jetbrains.util.filetype.DetectedFileInfo;
import com.jetbrains.util.filetype.FileProperties;
import com.jetbrains.util.filetype.FileType;
import com.jetbrains.util.filetype.FileTypeDetector;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.channels.SeekableByteChannel;
import java.util.EnumSet;
import java.util.stream.Stream;

class FileTypeDetectorTest {

  @ParameterizedTest
  @MethodSource("DetectFileTypeTestProvider")
  void DetectFileTypeTest(String filename, FileType expectedFileType,
                          EnumSet<FileProperties> expectedFileProperties,
                          boolean expectedPartial) throws Exception {
    DetectedFileInfo result;
    try (SeekableByteChannel channel = TestUtil.getTestByteChannel(filename)) {
      result = FileTypeDetector.detectFileType(channel);
    }

    Assertions.assertEquals(expectedFileType, result.fileType());
    Assertions.assertEquals(expectedFileProperties, result.fileProperties());
    Assertions.assertEquals(expectedPartial, result.partial());
  }

  static Stream<Arguments> DetectFileTypeTestProvider() {
    return Stream.of(
      Arguments.of("error0", FileType.Unknown, e(FileProperties.UnknownType), false),
      Arguments.of("error4", FileType.Unknown, e(FileProperties.UnknownType), false),
      Arguments.of("error_mach-o", FileType.MachO, e(FileProperties.UnknownType), true),
      Arguments.of("error_msi", FileType.Unknown, e(FileProperties.UnknownType), false),
      Arguments.of("error_pe", FileType.Pe, e(FileProperties.UnknownType), true),
      Arguments.of("wscadminui.x64.exe", FileType.Pe, e(FileProperties.ExecutableType), false),
      Arguments.of("wscadminui.x86.exe", FileType.Pe, e(FileProperties.ExecutableType), false),
      Arguments.of("winrsmgr.x64.dll", FileType.Pe, e(FileProperties.SharedLibraryType), false),
      Arguments.of("winrsmgr.x86.dll", FileType.Pe, e(FileProperties.SharedLibraryType), false),
      Arguments.of("2dac4b.msi", FileType.Msi, e(FileProperties.UnknownType), false),
      Arguments.of("env-wrapper.x64", FileType.MachO, e(FileProperties.ExecutableType, FileProperties.Signed), false),
      Arguments.of("libMonoSupportW.x64.dylib", FileType.MachO, e(FileProperties.SharedLibraryType, FileProperties.Signed), false),
      Arguments.of("fat.dylib", FileType.MachO, e(FileProperties.SharedLibraryType, FileProperties.MultiArch), false),
      Arguments.of("x64.dylib", FileType.MachO, e(FileProperties.SharedLibraryType), false),
      Arguments.of("x86.dylib", FileType.MachO, e(FileProperties.SharedLibraryType), false),
      Arguments.of("fat.bundle", FileType.MachO, e(FileProperties.BundleType, FileProperties.MultiArch), false),
      Arguments.of("x64.bundle", FileType.MachO, e(FileProperties.BundleType), false),
      Arguments.of("x86.bundle", FileType.MachO, e(FileProperties.BundleType), false),
      Arguments.of("cat", FileType.MachO, e(FileProperties.ExecutableType, FileProperties.MultiArch, FileProperties.Signed), false),
      Arguments.of("fsnotifier", FileType.MachO, e(FileProperties.ExecutableType, FileProperties.MultiArch), false),
      Arguments.of("tempfile.x64", FileType.Elf, e(FileProperties.ExecutableType), false),
      Arguments.of("libulockmgr.so.1.0.1.x64", FileType.Elf, e(FileProperties.SharedLibraryType), false),
      Arguments.of("catsay.ppc64", FileType.Elf, e(FileProperties.ExecutableType), false),
      Arguments.of("catsay.x86", FileType.Elf, e(FileProperties.ExecutableType), false),
      Arguments.of("vl805", FileType.Elf, e(FileProperties.ExecutableType), false),
      Arguments.of("libpcprofile.so", FileType.Elf, e(FileProperties.SharedLibraryType), false),
      Arguments.of("System.Security.Principal.Windows.dll", FileType.Pe,
        e(FileProperties.SharedLibraryType, FileProperties.Managed, FileProperties.Signed), false),
      Arguments.of("api-ms-win-core-rtlsupport-l1-1-0.dll", FileType.Pe,
        e(FileProperties.SharedLibraryType, FileProperties.Signed), false),
      Arguments.of("Armature.Interface.dll", FileType.Pe,
        e(FileProperties.SharedLibraryType, FileProperties.Managed), false),
      Arguments.of("1.sh", FileType.ShebangScript, e(FileProperties.ExecutableType), false),
      Arguments.of("2.sh", FileType.ShebangScript, e(FileProperties.ExecutableType), false)
    );
  }

  @SafeVarargs
  private static <T extends Enum<T>> EnumSet<T> e(T... items) {
    return TestUtil.enumSetOf(items);
  }
}
