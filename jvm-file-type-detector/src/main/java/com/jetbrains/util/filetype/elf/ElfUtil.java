package com.jetbrains.util.filetype.elf;

import com.jetbrains.util.filetype.io.BinaryReader;
import com.jetbrains.util.filetype.io.ReadUtils;
import com.jetbrains.util.filetype.io.SeekOrigin;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;

public final class ElfUtil {
  private ElfUtil() {
  }

  public static ElfInfo GetElfInfo(SeekableByteChannel stream) throws java.io.IOException {
    BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));
    try {
      if (Integer.toUnsignedLong(reader.ReadUInt32Be()) != 0x7F454C46L)
        throw new IllegalStateException("Unknown format");

      ElfClass ei_class;
      int classVal = reader.ReadByte() & 0xFF;
      if (classVal == 1) {
        ei_class = ElfClass.ELFCLASS32;
      } else if (classVal == 2) {
        ei_class = ElfClass.ELFCLASS64;
      } else {
        throw new IllegalStateException("Inconsistent ELF class");
      }

      boolean isBe;
      ElfData ei_data;
      int dataVal = reader.ReadByte() & 0xFF;
      if (dataVal == 1) {
        isBe = false;
        ei_data = ElfData.ELFDATA2LSB;
      } else if (dataVal == 2) {
        isBe = true;
        ei_data = ElfData.ELFDATA2MSB;
      } else {
        throw new IllegalStateException("Inconsistent ELF data");
      }

      ElfVersion version = ElfVersion.fromValue(reader.ReadByte());
      if (version != ElfVersion.EV_CURRENT)
        throw new IllegalStateException("Inconsistent ELF version");

      ElfOsAbi osabi = ElfOsAbi.fromValue(reader.ReadByte());
      byte osAbiVersion = reader.ReadByte();

      ElfType type;
      ElfMachine machine;
      long flags;
      String interpreter = null;

      ReadUtils.seek(stream, 7, SeekOrigin.Current); // skip EI_PAD

      if (ei_class == ElfClass.ELFCLASS32) {
        type = ElfType.fromValue(reader.ReadUInt16(isBe) & 0xFFFF);
        machine = ElfMachine.fromValue(reader.ReadUInt16(isBe) & 0xFFFF);
        ElfVersion e_version32 = ElfVersion.fromValue((byte) reader.ReadUInt32(isBe));
        if (e_version32 != ElfVersion.EV_CURRENT)
          throw new IllegalStateException("Invalid version of ELF32 program header");

        ReadUtils.seek(stream, 4, SeekOrigin.Current); // skip e_entry
        int ePhOff32 = reader.ReadUInt32(isBe);
        ReadUtils.seek(stream, 4, SeekOrigin.Current); // skip e_shoff
        flags = Integer.toUnsignedLong(reader.ReadUInt32(isBe));
        ReadUtils.seek(stream, 2, SeekOrigin.Current); // skip e_ehsize
        short e_phentsize32 = reader.ReadUInt16(isBe);
        short ePhNum32 = reader.ReadUInt16(isBe);
        ReadUtils.seek(stream, Integer.toUnsignedLong(ePhOff32), SeekOrigin.Begin);
        int phi = ePhNum32 & 0xFFFF;

        while (phi-- > 0) {
          int p_type = reader.ReadUInt32(isBe);
          if (p_type == ElfSegmentType.PT_INTERP) {
            int pOffset32 = reader.ReadUInt32(isBe);
            ReadUtils.seek(stream, 8, SeekOrigin.Current); // skip p_vaddr, p_paddr
            int pFileSz32 = reader.ReadUInt32(isBe);
            ReadUtils.seek(stream, Integer.toUnsignedLong(pOffset32), SeekOrigin.Begin);
            interpreter = reader.ReadString((int) Integer.toUnsignedLong(pFileSz32) - 1);
            break;
          }
          ReadUtils.seek(stream, (e_phentsize32 & 0xFFFFL) - 4, SeekOrigin.Current);
        }
      } else if (ei_class == ElfClass.ELFCLASS64) {
        type = ElfType.fromValue(reader.ReadUInt16(isBe) & 0xFFFF);
        machine = ElfMachine.fromValue(reader.ReadUInt16(isBe) & 0xFFFF);
        ElfVersion e_version64 = ElfVersion.fromValue((byte) reader.ReadUInt32(isBe));
        if (e_version64 != ElfVersion.EV_CURRENT)
          throw new IllegalStateException("Invalid version of ELF64 program header");

        ReadUtils.seek(stream, 8, SeekOrigin.Current); // skip e_entry
        long ePhOff64 = reader.ReadUInt64(isBe);
        ReadUtils.seek(stream, 8, SeekOrigin.Current); // skip e_shoff
        flags = Integer.toUnsignedLong(reader.ReadUInt32(isBe));
        ReadUtils.seek(stream, 2, SeekOrigin.Current); // skip e_ehsize
        short e_phentsize64 = reader.ReadUInt16(isBe);
        short ePhNum64 = reader.ReadUInt16(isBe);
        ReadUtils.seek(stream, ePhOff64, SeekOrigin.Begin);
        int phi = ePhNum64 & 0xFFFF;

        while (phi-- > 0) {
          int p_type = reader.ReadUInt32(isBe);
          if (p_type == ElfSegmentType.PT_INTERP) {
            ReadUtils.seek(stream, 4, SeekOrigin.Current); // skip p_flags
            long pOffset64 = reader.ReadUInt64(isBe);
            ReadUtils.seek(stream, 16, SeekOrigin.Current); // skip p_vaddr, p_paddr
            long pFileSz64 = reader.ReadUInt64(isBe);
            ReadUtils.seek(stream, pOffset64, SeekOrigin.Begin);
            interpreter = reader.ReadString((int) pFileSz64 - 1);
            break;
          }
          ReadUtils.seek(stream, (e_phentsize64 & 0xFFFFL) - 4, SeekOrigin.Current);
        }
      } else {
        throw new IllegalStateException("Unknown ELF class");
      }

      return new ElfInfo(ei_class, ei_data, osabi, osAbiVersion, type, machine, flags, interpreter);
    } catch (IOException ex) {
      throw new IllegalStateException("Unknown format");
    }
  }
}
