package com.jetbrains.util.filetype;

import com.jetbrains.util.filetype.io.BinaryReader;
import com.jetbrains.util.filetype.io.ReadUtils;
import com.jetbrains.util.filetype.io.SeekOrigin;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class FileTypeDetector {
  private FileTypeDetector() {
  }

  public static AbstractMap.SimpleImmutableEntry<FileType, EnumSet<FileProperties>> detectFileType(SeekableByteChannel stream) {
    EnumSet<FileProperties> res = isPe(stream);
    if (res != null)
      return pair(FileType.Pe, res);

    res = isMsi(stream);
    if (res != null)
      return pair(FileType.Msi, res);

    AbstractMap.SimpleImmutableEntry<EnumSet<FileProperties>, List<ProcessorArchitecture>> machoResult = tryParseMachO(stream);
    if (machoResult != null)
      return pair(FileType.MachO, machoResult.getKey());

    res = isElf(stream);
    if (res != null)
      return pair(FileType.Elf, res);

    res = isShebangScript(stream);
    if (res != null)
      return pair(FileType.ShebangScript, res);

    return pair(FileType.Unknown, enumSetOf(FileProperties.UnknownType));
  }

  private static @Nullable EnumSet<FileProperties> isPe(SeekableByteChannel stream) {
    try {
      BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));

      if ((reader.readUInt16() & 0xFFFF) != 0x5A4D) // IMAGE_DOS_SIGNATURE
        return null;

      ReadUtils.seek(stream, 0x3C, SeekOrigin.Begin); // IMAGE_DOS_HEADER::e_lfanew
      ReadUtils.seek(stream, Integer.toUnsignedLong(reader.readUInt32()), SeekOrigin.Begin);
      if (reader.readUInt32() != 0x00004550) // IMAGE_NT_SIGNATURE
        return null;
      ReadUtils.seek(stream, 0x12, SeekOrigin.Current); // IMAGE_FILE_HEADER::Characteristics

      EnumSet<FileProperties> fileProperties = enumSetOf(
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

      return fileProperties;
    } catch (IOException ex) {
      return null;
    }
  }

  private static @Nullable EnumSet<FileProperties> isMsi(SeekableByteChannel stream) {
    // Note: OLE Compound File format (OLECF) by Microsoft
    try {
      BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));
      // OLE CF magic 0xE11AB1A1E011CFD0
      if (reader.readInt64() != -2226271756974174256L)
        return null;
      return enumSetOf(FileProperties.UnknownType);
    } catch (IOException ex) {
      return null;
    }
  }

  private static @Nullable EnumSet<FileProperties> isElf(SeekableByteChannel stream) {
    try {
      BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));

      // Note: See https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
      if (reader.readUInt32() != 0x464C457F) // e_ident[EI_MAG0..EI_MAG3] (LE: \x7FELF)
        return null;

      int classVal = reader.readByte() & 0xFF; // e_ident[EI_CLASS]
      boolean is64;
      if (classVal == 1) {
        is64 = false;
      } else if (classVal == 2) {
        is64 = true;
      } else {
        return null;
      }

      int dataVal = reader.readByte() & 0xFF; // e_ident[EI_DATA]
      boolean isBe;
      if (dataVal == 1) {
        isBe = false;
      } else if (dataVal == 2) {
        isBe = true;
      } else {
        return null;
      }

      if ((reader.readByte() & 0xFF) != 1) // e_ident[EI_VERSION]
        return null;

      ReadUtils.seek(stream, 9, SeekOrigin.Current);
      int eType = reader.readUInt16Le(isBe) & 0xFFFF; // e_type
      ReadUtils.seek(stream, 2, SeekOrigin.Current);

      if (Integer.toUnsignedLong(reader.readUInt32Le(isBe)) != 1L) // e_version
        return null;

      if (eType == 0x02) return enumSetOf(FileProperties.ExecutableType); // ET_EXEC
      if (eType != 0x03) return enumSetOf(FileProperties.UnknownType); // not ET_DYN

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

      return hasExecutable ? enumSetOf(FileProperties.ExecutableType) : enumSetOf(FileProperties.SharedLibraryType);
    } catch (IOException ex) {
      return null;
    }
  }

  /** Returns (fileProperties, architectureList) or null if not a Mach-O. */
  private static AbstractMap.@Nullable SimpleImmutableEntry<EnumSet<FileProperties>, List<ProcessorArchitecture>> tryParseMachO(SeekableByteChannel stream) {
    try {
      BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));
      long masterMagic = Integer.toUnsignedLong(reader.readUInt32()); // mach_header::magic / mach_header64::magic / fat_header::magic
      AbstractMap.SimpleImmutableEntry<EnumSet<FileProperties>, List<ProcessorArchitecture>> result =
        readFatHeader(reader, stream, masterMagic);
      if (result == null)
        result = readHeader(reader, stream, masterMagic);
      return result;
    } catch (IOException ex) {
      return null;
    }
  }

  private static AbstractMap.@Nullable SimpleImmutableEntry<EnumSet<FileProperties>, List<ProcessorArchitecture>> readHeader(
    BinaryReader reader, SeekableByteChannel stream, long magic) throws IOException {

    // Note: See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h
    boolean isLe32 = magic == 0xFEEDFACEL; // MH_MAGIC
    boolean isLe64 = magic == 0xFEEDFACFL; // MH_MAGIC_64
    boolean isBe32 = magic == 0xCEFAEDFEL; // MH_CIGAM
    boolean isBe64 = magic == 0xCFFAEDFEL; // MH_CIGAM_64

    if (!isLe32 && !isLe64 && !isBe32 && !isBe64)
      return null;

    final int CPU_ARCH_ABI64 = 0x01000000;
    final int CPU_TYPE_X86 = 7;
    final int CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
    final int CPU_TYPE_ARM64 = 12 | CPU_ARCH_ABI64;

    boolean isBe = isBe32 || isBe64;
    int cpuType = reader.readUInt32Le(isBe); // mach_header::cputype / mach_header_64::cputype
    ProcessorArchitecture cputype;
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
    EnumSet<FileProperties> fileProperties = enumSetOf(
      switch (fileType) {
        case 0x2 -> FileProperties.ExecutableType;    // MH_EXECUTE
        case 0x6 -> FileProperties.SharedLibraryType; // MH_DYLIB
        case 0x8 -> FileProperties.BundleType;        // MH_BUNDLE
        default -> FileProperties.UnknownType;
      }
    );

    int ncmds = reader.readUInt32Le(isBe); // mach_header::ncmds / mach_header_64::ncmds
    ReadUtils.seek(stream, (isLe64 || isBe64) ? 0xC : 0x8, SeekOrigin.Current); // load_command[0]

    while (ncmds-- > 0) {
      int cmd = reader.readUInt32Le(isBe);     // load_command::cmd
      int cmdsize = reader.readUInt32Le(isBe); // load_command::cmdsize
      ReadUtils.seek(stream, Integer.toUnsignedLong(cmdsize) - 8, SeekOrigin.Current);

      if (Integer.toUnsignedLong(cmd) == 0x1DL) // LC_CODE_SIGNATURE
        fileProperties.add(FileProperties.Signed);
    }

    List<ProcessorArchitecture> archList = Collections.singletonList(cputype);
    return pair(fileProperties, archList);
  }

  private static AbstractMap.@Nullable SimpleImmutableEntry<EnumSet<FileProperties>, List<ProcessorArchitecture>> readFatHeader(
    BinaryReader reader, SeekableByteChannel stream, long magic) throws IOException {

    // Note: See https://opensource.apple.com/source/xnu/xnu-344/EXTERNAL_HEADERS/mach-o/fat.h
    boolean isLe32 = magic == 0xCAFEBABEL; // FAT_MAGIC
    boolean isLe64 = magic == 0xCAFEBABFL; // FAT_MAGIC_64
    boolean isBe32 = magic == 0xBEBAFECAL; // FAT_CIGAM
    boolean isBe64 = magic == 0xBFBAFECAL; // FAT_CIGAM_64

    if (!isLe32 && !isLe64 && !isBe32 && !isBe64)
      return null;

    boolean isBe = isBe32 || isBe64;
    int nFatArch = reader.readUInt32Le(isBe); // fat_header::nfat_arch
    List<Long> offsets = new ArrayList<>();

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

    List<ProcessorArchitecture> fileArchitecturesList = new ArrayList<>();
    List<@Nullable EnumSet<FileProperties>> filePropertiesList = new ArrayList<>();
    boolean anyNull = false;

    for (long offset : offsets) {
      ReadUtils.seek(stream, offset, SeekOrigin.Begin);
      long hdrMagic = Integer.toUnsignedLong(reader.readUInt32()); // mach_header::magic / mach_header64::magic
      AbstractMap.SimpleImmutableEntry<EnumSet<FileProperties>, List<ProcessorArchitecture>> fileProperties =
        readHeader(reader, stream, hdrMagic);
      if (fileProperties != null) {
        fileArchitecturesList.add(fileProperties.getValue().get(0));
        filePropertiesList.add(fileProperties.getKey());
      } else {
        anyNull = true;
        filePropertiesList.add(null);
      }
    }

    if (filePropertiesList.isEmpty())
      return pair(enumSetOf(FileProperties.UnknownType), Collections.emptyList());

    // One of headers is invalid
    if (anyNull)
      return null;

    boolean signed = filePropertiesList.stream().allMatch(p -> p != null && p.contains(FileProperties.Signed));

    // Check that all headers have compatible file properties (ignoring signed flag)
    Set<EnumSet<FileProperties>> distinct = new HashSet<>();
    for (@Nullable EnumSet<FileProperties> fp : filePropertiesList) {
      if (fp == null) continue;
      EnumSet<FileProperties> copy = EnumSet.copyOf(fp);
      if (!signed) copy.remove(FileProperties.Signed);
      distinct.add(copy);
    }

    if (distinct.size() > 1) {
      // Headers are incompatible
      return null;
    }

    EnumSet<FileProperties> totalFileProperty = filePropertiesList.get(0);
    if (filePropertiesList.size() > 1 && totalFileProperty != null) {
      totalFileProperty.add(FileProperties.MultiArch);
      if (!signed) {
        totalFileProperty.remove(FileProperties.Signed);
      }
    }

    return pair(totalFileProperty, fileArchitecturesList);
  }

  private static @Nullable EnumSet<FileProperties> isShebangScript(SeekableByteChannel stream) {
    try {
      BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));
      if ((char) (reader.readByte() & 0xFF) == '#' && (char) (reader.readByte() & 0xFF) == '!') {
        char c = (char) (reader.readByte() & 0xFF);
        while (c == ' ' || c == '\t')
          c = (char) (reader.readByte() & 0xFF);
        if (c == '/')
          return enumSetOf(FileProperties.ExecutableType);
      }
      return null;
    } catch (IOException ex) {
      return null;
    }
  }

  private static <T extends Enum<T>> EnumSet<T> enumSetOf(T item) {
    return EnumSet.of(item);
  }

  private static <K extends @Nullable Object, V extends @Nullable Object> AbstractMap.SimpleImmutableEntry<K, V> pair(K key, V value) {
    return new AbstractMap.SimpleImmutableEntry<>(key, value);
  }
}
