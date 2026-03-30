package com.jetbrains.util.filetype.elf.tests;

import com.jetbrains.util.filetype.TestUtil;
import com.jetbrains.util.filetype.elf.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

class ElfUtilTest {

  @ParameterizedTest
  @MethodSource("ElfInfoTestProvider")
  void ElfInfoTest(String filename, ElfClass expectedClass, ElfData expectedData, ElfOsAbi expectedOsAbi,
                   byte expectedOsAbiVersion, ElfType expectedType, ElfMachine expectedMachine,
                   long expectedFlags, String expectedInterpreter) throws Exception {
    ElfInfo elfInfo;
    try (var channel = TestUtil.getTestByteChannel("elf", filename)) {
      elfInfo = ElfUtil.getElfInfo(channel);
    }

    Assertions.assertNotNull(elfInfo);
    Assertions.assertEquals(expectedClass, elfInfo.getElfClass());
    Assertions.assertEquals(expectedData, elfInfo.getData());
    Assertions.assertEquals(expectedOsAbi, elfInfo.getOsAbi());
    Assertions.assertEquals(expectedOsAbiVersion, elfInfo.getOsAbiVersion());
    Assertions.assertEquals(expectedType, elfInfo.getType());
    Assertions.assertEquals(expectedMachine, elfInfo.getMachine());
    Assertions.assertEquals(expectedFlags, elfInfo.getFlags());
    Assertions.assertEquals(expectedInterpreter, elfInfo.getInterpreter());
  }

  static Stream<Arguments> ElfInfoTestProvider() {
    // Note: Some architectures don't have the difference in interpreters!
    return Stream.of(
      // @formatter:off
      Arguments.of("busybox-static.nixos-aarch64"  , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_EXEC, ElfMachine.EM_AARCH64    , 0x0L , null),
      Arguments.of("busybox-static.nixos-x86_64"   , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_EXEC, ElfMachine.EM_X86_64     , 0x0L , null),
      Arguments.of("busybox.alpine-aarch64"        , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_AARCH64    , 0x0L , "/lib/ld-musl-aarch64.so.1"),
      Arguments.of("busybox.alpine-armhf"          , ElfClass.ELFCLASS32, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_ARM        , 0x5000400L , "/lib/ld-musl-armhf.so.1"),
      Arguments.of("busybox.alpine-ppc64le"        , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_PPC64      , 0x2L , "/lib/ld-musl-powerpc64le.so.1"),
      Arguments.of("busybox.alpine-s390x"          , ElfClass.ELFCLASS64, ElfData.ELFDATA2MSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_S390       , 0x0L , "/lib/ld-musl-s390x.so.1"),
      Arguments.of("busybox.alpine-i386"           , ElfClass.ELFCLASS32, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_386        , 0x0L , "/lib/ld-musl-i386.so.1"),
      Arguments.of("busybox.alpine-x86_64"         , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_X86_64     , 0x0L , "/lib/ld-musl-x86_64.so.1"),
      Arguments.of("coreutils.nixos-aarch64"       , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_EXEC, ElfMachine.EM_AARCH64    , 0x0L , "/nix/store/c1nqsqwl9allxbxhqx3iqfxk363qrnzv-glibc-2.32-54/lib/ld-linux-aarch64.so.1"),
      Arguments.of("coreutils.nixos-x86_64"        , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_EXEC, ElfMachine.EM_X86_64     , 0x0L , "/nix/store/jsp3h3wpzc842j0rz61m5ly71ak6qgdn-glibc-2.32-54/lib/ld-linux-x86-64.so.2"),
      Arguments.of("grep.android-i386"             , ElfClass.ELFCLASS32, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_386        , 0x0L , "/system/bin/linker"),
      Arguments.of("grep.android-x86_64"           , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_X86_64     , 0x0L , "/system/bin/linker64"),
      Arguments.of("mktemp.freebsd-aarch64"        , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_FREEBSD, (byte)0, ElfType.ET_EXEC, ElfMachine.EM_AARCH64    , 0x0L , "/libexec/ld-elf.so.1"),
      Arguments.of("mktemp.freebsd-i386"           , ElfClass.ELFCLASS32, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_FREEBSD, (byte)0, ElfType.ET_EXEC, ElfMachine.EM_386        , 0x0L , "/libexec/ld-elf.so.1"),
      Arguments.of("mktemp.freebsd-powerpc"        , ElfClass.ELFCLASS32, ElfData.ELFDATA2MSB, ElfOsAbi.ELFOSABI_FREEBSD, (byte)0, ElfType.ET_EXEC, ElfMachine.EM_PPC        , 0x0L , "/libexec/ld-elf.so.1"),
      Arguments.of("mktemp.freebsd-powerpc64"      , ElfClass.ELFCLASS64, ElfData.ELFDATA2MSB, ElfOsAbi.ELFOSABI_FREEBSD, (byte)0, ElfType.ET_EXEC, ElfMachine.EM_PPC64      , 0x2L , "/libexec/ld-elf.so.1"),
      Arguments.of("mktemp.freebsd-powerpc64le"    , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_FREEBSD, (byte)0, ElfType.ET_EXEC, ElfMachine.EM_PPC64      , 0x2L , "/libexec/ld-elf.so.1"),
      Arguments.of("mktemp.freebsd-riscv64"        , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_EXEC, ElfMachine.EM_RISCV      , 0x5L , "/libexec/ld-elf.so.1"),
      Arguments.of("mktemp.freebsd-sparc64"        , ElfClass.ELFCLASS64, ElfData.ELFDATA2MSB, ElfOsAbi.ELFOSABI_FREEBSD, (byte)0, ElfType.ET_EXEC, ElfMachine.EM_SPARCV9    , 0x2L , "/libexec/ld-elf.so.1"),
      Arguments.of("mktemp.freebsd-x86_64"         , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_FREEBSD, (byte)0, ElfType.ET_EXEC, ElfMachine.EM_X86_64     , 0x0L , "/libexec/ld-elf.so.1"),
      Arguments.of("mktemp.gentoo-armv7a_hf-uclibc", ElfClass.ELFCLASS32, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_ARM        , 0x5000400L , "/lib/ld-uClibc.so.0"),
      Arguments.of("mktemp.gentoo-armv4tl"         , ElfClass.ELFCLASS32, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_ARM        , 0x5000200L , "/lib/ld-linux.so.3"),
      Arguments.of("mktemp.gentoo-hppa2.0"         , ElfClass.ELFCLASS32, ElfData.ELFDATA2MSB, ElfOsAbi.ELFOSABI_LINUX  , (byte)0, ElfType.ET_DYN , ElfMachine.EM_PARISC     , 0x210L , "/lib/ld.so.1"),
      Arguments.of("mktemp.gentoo-ia64"            , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_IA_64      , 0x10L , "/lib/ld-linux-ia64.so.2"),
      Arguments.of("mktemp.gentoo-m68k"            , ElfClass.ELFCLASS32, ElfData.ELFDATA2MSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_68K        , 0x0L , "/lib/ld.so.1"),
      Arguments.of("mktemp.gentoo-sparc"           , ElfClass.ELFCLASS32, ElfData.ELFDATA2MSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_SPARC32PLUS, 0xB00L , "/lib/ld-linux.so.2"),
      Arguments.of("mktemp.gentoo-mipsel3-uclibc"  , ElfClass.ELFCLASS32, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)1, ElfType.ET_EXEC, ElfMachine.EM_MIPS       , 0x20001105L, "/lib/ld-uClibc.so.0"),
      Arguments.of("mktemp.openbsd-alpha"          , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_ALPHA      , 0x0L , "/usr/libexec/ld.so"),
      Arguments.of("mktemp.openbsd-armv7"          , ElfClass.ELFCLASS32, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_ARM        , 0x5000200L , "/usr/libexec/ld.so"),
      Arguments.of("mktemp.openbsd-hppa"           , ElfClass.ELFCLASS32, ElfData.ELFDATA2MSB, ElfOsAbi.ELFOSABI_HPUX   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_PARISC     , 0x210L , "/usr/libexec/ld.so"),
      Arguments.of("mktemp.openbsd-i386"           , ElfClass.ELFCLASS32, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_386        , 0x0L , "/usr/libexec/ld.so"),
      Arguments.of("mktemp.openbsd-powerpc64"      , ElfClass.ELFCLASS64, ElfData.ELFDATA2MSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_PPC64      , 0x2L , "/usr/libexec/ld.so"),
      Arguments.of("mktemp.openbsd-landisk"        , ElfClass.ELFCLASS32, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_SH         , 0xBL , "/usr/libexec/ld.so"),
      Arguments.of("mktemp.openbsd-luna88k"        , ElfClass.ELFCLASS32, ElfData.ELFDATA2MSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_EXEC, ElfMachine.EM_88K        , 0x0L , "/usr/libexec/ld.so"),
      Arguments.of("mktemp.openbsd-macppc"         , ElfClass.ELFCLASS32, ElfData.ELFDATA2MSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_PPC        , 0x0L , "/usr/libexec/ld.so"),
      Arguments.of("mktemp.openbsd-octeon"         , ElfClass.ELFCLASS64, ElfData.ELFDATA2MSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_MIPS       , 0x20000007L , "/usr/libexec/ld.so"),
      Arguments.of("mktemp.openbsd-sparc64"        , ElfClass.ELFCLASS64, ElfData.ELFDATA2MSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_SPARCV9    , 0x2L , "/usr/libexec/ld.so"),
      Arguments.of("mktemp.openbsd-x86_64"         , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_X86_64     , 0x0L , "/usr/libexec/ld.so"),
      Arguments.of("nologin.opensuse-i586"         , ElfClass.ELFCLASS32, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_386        , 0x0L , "/lib/ld-linux.so.2"),
      Arguments.of("nologin.opensuse-ppc64le"      , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_PPC64      , 0x2L , "/lib64/ld64.so.2"),
      Arguments.of("nologin.opensuse-s390x"        , ElfClass.ELFCLASS64, ElfData.ELFDATA2MSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_S390       , 0x0L , "/lib/ld64.so.1"),
      Arguments.of("tempfile.ubuntu-aarch64"       , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_AARCH64    , 0x0L , "/lib/ld-linux-aarch64.so.1"),
      Arguments.of("tempfile.ubuntu-armhf"         , ElfClass.ELFCLASS32, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_ARM        , 0x5000400L , "/lib/ld-linux-armhf.so.3"),
      Arguments.of("tempfile.ubuntu-i386"          , ElfClass.ELFCLASS32, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_386        , 0x0L , "/lib/ld-linux.so.2"),
      Arguments.of("tempfile.ubuntu-x86_64"        , ElfClass.ELFCLASS64, ElfData.ELFDATA2LSB, ElfOsAbi.ELFOSABI_NONE   , (byte)0, ElfType.ET_DYN , ElfMachine.EM_X86_64     , 0x0L , "/lib64/ld-linux-x86-64.so.2")
      // @formatter:on
    );
  }
}
