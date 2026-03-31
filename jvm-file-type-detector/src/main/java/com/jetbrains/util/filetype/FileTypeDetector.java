package com.jetbrains.util.filetype;

import com.jetbrains.util.filetype.io.BinaryReader;
import com.jetbrains.util.filetype.io.ReadUtils;
import com.jetbrains.util.filetype.io.SeekOrigin;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class FileTypeDetector {
  private FileTypeDetector() {
  }

  private record FormatResult(EnumSet<FileProperties> fileProperties, boolean partial) {
  }

  private record MachoResult(EnumSet<FileProperties> fileProperties, List<ProcessorArchitecture> architectures, boolean partial) {
  }

  public static DetectedFileInfo detectFileType(SeekableByteChannel stream) {
    FormatResult pe = isPe(stream);
    if (pe != null)
      return new DetectedFileInfo(FileType.Pe, pe.fileProperties(), pe.partial());

    FormatResult msi = isMsi(stream);
    if (msi != null)
      return new DetectedFileInfo(FileType.Msi, msi.fileProperties(), msi.partial());

    MachoResult macho = tryParseMachO(stream);
    if (macho != null)
      return new DetectedFileInfo(FileType.MachO, macho.fileProperties(), macho.partial());

    FormatResult elf = isElf(stream);
    if (elf != null)
      return new DetectedFileInfo(FileType.Elf, elf.fileProperties(), elf.partial());

    FormatResult shebang = isShebangScript(stream);
    if (shebang != null)
      return new DetectedFileInfo(FileType.ShebangScript, shebang.fileProperties(), shebang.partial());

    return new DetectedFileInfo(FileType.Unknown, enumSetOf(FileProperties.UnknownType), false);
  }

  private static @Nullable FormatResult isPe(SeekableByteChannel stream) {
    boolean peConfirmed = false;
    EnumSet<FileProperties> fileProperties = null;
    try {
      BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));

      if ((reader.readUInt16() & 0xFFFF) != 0x5A4D) // IMAGE_DOS_SIGNATURE
        return null;

      ReadUtils.seek(stream, 0x3C, SeekOrigin.Begin); // IMAGE_DOS_HEADER::e_lfanew
      ReadUtils.seek(stream, Integer.toUnsignedLong(reader.readUInt32()), SeekOrigin.Begin);
      if (reader.readUInt32() != 0x00004550) // IMAGE_NT_SIGNATURE
        return null;

      peConfirmed = true;

      ReadUtils.seek(stream, 0x12, SeekOrigin.Current); // IMAGE_FILE_HEADER::Characteristics

      fileProperties = enumSetOf(
        switch (reader.readUInt16() & 0x2002) {
          case 0x2002 -> FileProperties.SharedLibraryType; // IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL
          case 0x0002 -> FileProperties.ExecutableType;    // IMAGE_FILE_EXECUTABLE_IMAGE
          default -> FileProperties.UnknownType;
        }
      );

      int magic = reader.readUInt16() & 0xFFFF; // IMAGE_OPTIONAL_HEADER32::Magic / IMAGE_OPTIONAL_HEADER64::Magic
      if (magic == 0x10b) {
        ReadUtils.seek(stream, 0x60L - 2, SeekOrigin.Current); // Skip IMAGE_OPTIONAL_HEADER32 to DataDirectory
      } else if (magic == 0x20b) {
        ReadUtils.seek(stream, 0x70L - 2, SeekOrigin.Current); // Skip IMAGE_OPTIONAL_HEADER64 to DataDirectory
      }

      ReadUtils.seek(stream, 8L * 4L, SeekOrigin.Current); // DataDirectory + IMAGE_DIRECTORY_ENTRY_SECURITY
      int securityRva = reader.readUInt32();
      int securitySize = reader.readUInt32();

      if (securityRva != 0 && securitySize != 0)
        fileProperties.add(FileProperties.Signed);

      ReadUtils.seek(stream, 8L * 9L, SeekOrigin.Current); // DataDirectory + IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
      int comRva = reader.readUInt32();
      int comSize = reader.readUInt32();

      if (comRva != 0 && comSize != 0)
        fileProperties.add(FileProperties.Managed);

      return new FormatResult(fileProperties, false);
    } catch (IOException ex) {
      if (!peConfirmed) return null;
      return new FormatResult(fileProperties != null ? fileProperties : enumSetOf(FileProperties.UnknownType), true);
    }
  }

  private static @Nullable FormatResult isMsi(SeekableByteChannel stream) {
    // Note: OLE Compound File format (OLECF) by Microsoft
    try {
      BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));
      // OLE CF magic 0xE11AB1A1E011CFD0
      if (reader.readInt64() != -2226271756974174256L)
        return null;
      return new FormatResult(enumSetOf(FileProperties.UnknownType), false);
    } catch (IOException ex) {
      return null;
    }
  }

  private static @Nullable FormatResult isElf(SeekableByteChannel stream) {
    boolean elfConfirmed = false;
    int eType = -1;
    try {
      BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));

      // Note: See https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
      if (reader.readUInt32() != 0x464C457F) // e_ident[EI_MAG0..EI_MAG3] (LE: \x7FELF)
        return null;

      elfConfirmed = true;

      int classVal = reader.readByte() & 0xFF; // e_ident[EI_CLASS]
      boolean is64;
      if (classVal == 1) {
        is64 = false;
      } else if (classVal == 2) {
        is64 = true;
      } else {
        return new FormatResult(enumSetOf(FileProperties.UnknownType), true);
      }

      int dataVal = reader.readByte() & 0xFF; // e_ident[EI_DATA]
      boolean isBe;
      if (dataVal == 1) {
        isBe = false;
      } else if (dataVal == 2) {
        isBe = true;
      } else {
        return new FormatResult(enumSetOf(FileProperties.UnknownType), true);
      }

      if ((reader.readByte() & 0xFF) != 1) // e_ident[EI_VERSION]
        return new FormatResult(enumSetOf(FileProperties.UnknownType), true);

      ReadUtils.seek(stream, 9, SeekOrigin.Current);
      eType = reader.readUInt16Le(isBe) & 0xFFFF; // e_type
      ReadUtils.seek(stream, 2, SeekOrigin.Current);

      if (Integer.toUnsignedLong(reader.readUInt32Le(isBe)) != 1L) // e_version
        return new FormatResult(enumSetOf(FileProperties.UnknownType), true);

      if (eType == 0x02) return new FormatResult(enumSetOf(FileProperties.ExecutableType), false); // ET_EXEC
      if (eType != 0x03) return new FormatResult(enumSetOf(FileProperties.UnknownType), false);   // not ET_DYN

      ReadUtils.seek(stream, is64 ? 8 : 4, SeekOrigin.Current);
      long ePhOff; // e_phoff
      if (is64) {
        ePhOff = reader.readUInt64Le(isBe);
      } else {
        ePhOff = Integer.toUnsignedLong(reader.readUInt32Le(isBe));
      }

      ReadUtils.seek(stream, is64 ? 0x10 : 0xC, SeekOrigin.Current);
      int ePhNum = reader.readUInt16Le(isBe) & 0xFFFF; // e_phnum

      ReadUtils.seek(stream, ePhOff, SeekOrigin.Begin);

      boolean hasExecutable = false;

      while (ePhNum-- > 0) {
        if (reader.readUInt32Le(isBe) == 0x00000003) // PT_INTERP
          hasExecutable = true;
        ReadUtils.seek(stream, is64 ? 0x34 : 0x1C, SeekOrigin.Current);
      }

      return new FormatResult(
        hasExecutable ? enumSetOf(FileProperties.ExecutableType) : enumSetOf(FileProperties.SharedLibraryType),
        false
      );
    } catch (IOException ex) {
      if (!elfConfirmed) return null;
      if (eType == 0x02) return new FormatResult(enumSetOf(FileProperties.ExecutableType), true);   // ET_EXEC
      if (eType == 0x03) return new FormatResult(enumSetOf(FileProperties.SharedLibraryType), true); // ET_DYN
      return new FormatResult(enumSetOf(FileProperties.UnknownType), true);
    }
  }

  /** Returns MachoResult or null if not a Mach-O. */
  private static @Nullable MachoResult tryParseMachO(SeekableByteChannel stream) {
    try {
      BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));
      long masterMagic = Integer.toUnsignedLong(reader.readUInt32()); // mach_header::magic / mach_header64::magic / fat_header::magic
      MachoResult result = readFatHeader(reader, stream, masterMagic);
      if (result == null)
        result = readHeader(reader, stream, masterMagic);
      return result;
    } catch (IOException ex) {
      return null;
    }
  }

  private static @Nullable MachoResult readHeader(BinaryReader reader, SeekableByteChannel stream, long magic) throws IOException {
    // Note: See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h
    boolean isLe32 = magic == 0xFEEDFACEL; // MH_MAGIC
    boolean isLe64 = magic == 0xFEEDFACFL; // MH_MAGIC_64
    boolean isBe32 = magic == 0xCEFAEDFEL; // MH_CIGAM
    boolean isBe64 = magic == 0xCFFAEDFEL; // MH_CIGAM_64

    if (!isLe32 && !isLe64 && !isBe32 && !isBe64)
      return null;

    // Mach-O magic confirmed - return partial result on failure from here on
    boolean isBe = isBe32 || isBe64;

    final int CPU_ARCH_ABI64 = 0x01000000;
    final int CPU_TYPE_X86 = 7;
    final int CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
    final int CPU_TYPE_ARM64 = 12 | CPU_ARCH_ABI64;

    ProcessorArchitecture cputype = null;
    EnumSet<FileProperties> fileProperties = null;

    try {
      int cpuType = reader.readUInt32Le(isBe); // mach_header::cputype / mach_header_64::cputype
      if (cpuType == CPU_TYPE_X86) {
        cputype = ProcessorArchitecture.PROCESSOR_ARCHITECTURE_INTEL;
      } else if (cpuType == CPU_TYPE_X86_64) {
        cputype = ProcessorArchitecture.PROCESSOR_ARCHITECTURE_AMD64;
      } else if (cpuType == CPU_TYPE_ARM64) {
        cputype = ProcessorArchitecture.PROCESSOR_ARCHITECTURE_ARM64;
      } else {
        cputype = ProcessorArchitecture.PROCESSOR_ARCHITECTURE_UNKNOWN;
      }

      ReadUtils.seek(stream, 4, SeekOrigin.Current);

      int fileType = reader.readUInt32Le(isBe); // mach_header::filetype / mach_header_64::filetype
      fileProperties = enumSetOf(
        switch (fileType) {
          case 0x2 -> FileProperties.ExecutableType;    // MH_EXECUTE
          case 0x6 -> FileProperties.SharedLibraryType; // MH_DYLIB
          case 0x8 -> FileProperties.BundleType;        // MH_BUNDLE
          default -> FileProperties.UnknownType;
        }
      );

      int ncmds = reader.readUInt32Le(isBe); // mach_header::ncmds / mach_header_64::ncmds
      ReadUtils.seek(stream, (isLe64 || isBe64) ? 0xC : 0x8, SeekOrigin.Current); // load_command[0]

      boolean loadCommandsPartial = false;
      try {
        while (ncmds-- > 0) {
          int cmd = reader.readUInt32Le(isBe);     // load_command::cmd
          int cmdsize = reader.readUInt32Le(isBe); // load_command::cmdsize
          ReadUtils.seek(stream, Integer.toUnsignedLong(cmdsize) - 8, SeekOrigin.Current);

          if (Integer.toUnsignedLong(cmd) == 0x1DL) // LC_CODE_SIGNATURE
            fileProperties.add(FileProperties.Signed);
        }
      } catch (IOException ex) {
        loadCommandsPartial = true;
      }

      return new MachoResult(fileProperties, Collections.singletonList(cputype), loadCommandsPartial);
    } catch (IOException ex) {
      return new MachoResult(
        fileProperties != null ? fileProperties : enumSetOf(FileProperties.UnknownType),
        Collections.singletonList(cputype != null ? cputype : ProcessorArchitecture.PROCESSOR_ARCHITECTURE_UNKNOWN),
        true
      );
    }
  }

  private static @Nullable MachoResult readFatHeader(BinaryReader reader, SeekableByteChannel stream, long magic) throws IOException {
    // Note: See https://opensource.apple.com/source/xnu/xnu-344/EXTERNAL_HEADERS/mach-o/fat.h
    boolean isLe32 = magic == 0xCAFEBABEL; // FAT_MAGIC
    boolean isLe64 = magic == 0xCAFEBABFL; // FAT_MAGIC_64
    boolean isBe32 = magic == 0xBEBAFECAL; // FAT_CIGAM
    boolean isBe64 = magic == 0xBFBAFECAL; // FAT_CIGAM_64

    if (!isLe32 && !isLe64 && !isBe32 && !isBe64)
      return null;

    // Fat Mach-O magic confirmed - return partial result on failure from here on
    boolean isBe = isBe32 || isBe64;
    List<Long> offsets = new ArrayList<>();

    try {
      int nFatArch = reader.readUInt32Le(isBe); // fat_header::nfat_arch

      if (isBe64 || isLe64) {
        int n = nFatArch;
        while (n-- > 0) {
          ReadUtils.seek(stream, 8, SeekOrigin.Current);
          offsets.add(reader.readUInt64Le(isBe64)); // fat_arch_64::offset
          ReadUtils.seek(stream, 16, SeekOrigin.Current);
        }
      } else {
        int n = nFatArch;
        while (n-- > 0) {
          ReadUtils.seek(stream, 8, SeekOrigin.Current);
          offsets.add(Integer.toUnsignedLong(reader.readUInt32Le(isBe32))); // fat_arch::offset
          ReadUtils.seek(stream, 8, SeekOrigin.Current);
        }
      }
    } catch (IOException ex) {
      return new MachoResult(enumSetOf(FileProperties.UnknownType), Collections.emptyList(), true);
    }

    List<ProcessorArchitecture> fileArchitecturesList = new ArrayList<>();
    List<MachoResult> archResults = new ArrayList<>();
    boolean anyArchSkipped = false;

    for (long offset : offsets) {
      try {
        ReadUtils.seek(stream, offset, SeekOrigin.Begin);
        long hdrMagic = Integer.toUnsignedLong(reader.readUInt32()); // mach_header::magic / mach_header64::magic
        MachoResult archResult = readHeader(reader, stream, hdrMagic);
        if (archResult != null) {
          fileArchitecturesList.add(archResult.architectures().get(0));
          archResults.add(archResult);
        } else {
          anyArchSkipped = true;
        }
      } catch (IOException ex) {
        anyArchSkipped = true;
      }
    }

    if (archResults.isEmpty())
      return new MachoResult(enumSetOf(FileProperties.UnknownType), fileArchitecturesList, true);

    boolean anyArchPartial = anyArchSkipped || archResults.stream().anyMatch(MachoResult::partial);
    boolean signed = archResults.stream().allMatch(r -> r.fileProperties().contains(FileProperties.Signed));

    // Check that all headers have compatible file properties (ignoring signed flag)
    Set<EnumSet<FileProperties>> distinct = new HashSet<>();
    for (MachoResult archResult : archResults) {
      EnumSet<FileProperties> copy = EnumSet.copyOf(archResult.fileProperties());
      if (!signed) copy.remove(FileProperties.Signed);
      distinct.add(copy);
    }

    if (distinct.size() > 1) {
      // Headers are incompatible - return partial result
      return new MachoResult(enumSetOf(FileProperties.UnknownType), fileArchitecturesList, true);
    }

    EnumSet<FileProperties> totalFileProperty = archResults.get(0).fileProperties();
    if (archResults.size() > 1) {
      totalFileProperty.add(FileProperties.MultiArch);
      if (!signed) {
        totalFileProperty.remove(FileProperties.Signed);
      }
    }

    return new MachoResult(totalFileProperty, fileArchitecturesList, anyArchPartial);
  }

  private static @Nullable FormatResult isShebangScript(SeekableByteChannel stream) {
    try {
      BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));
      if ((char) (reader.readByte() & 0xFF) == '#' && (char) (reader.readByte() & 0xFF) == '!') {
        char c = (char) (reader.readByte() & 0xFF);
        while (c == ' ' || c == '\t')
          c = (char) (reader.readByte() & 0xFF);
        if (c == '/')
          return new FormatResult(enumSetOf(FileProperties.ExecutableType), false);
      }
      return null;
    } catch (IOException ex) {
      return null;
    }
  }

  private static <T extends Enum<T>> EnumSet<T> enumSetOf(T item) {
    return EnumSet.of(item);
  }
}
