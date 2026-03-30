package com.jetbrains.signatureverifier.cf;

import com.jetbrains.signatureverifier.InvalidDataException;
import com.jetbrains.util.filetype.io.BinaryReader;
import com.jetbrains.util.filetype.io.ReadUtils;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;

public class CompoundFileHeader {
  /** Size of sectors in power-of-two */
  public final int SectorShift;

  /** Size of mini-sectors in power-of-two, typically 6 indicating 64-byte mini-sectors */
  public final int MiniSectorShift;

  /** Number of SECTs in directory chain for 4 KB sectors, must be zero for 512-byte sectors */
  public final int SectDirCount;

  /** Number of SECTs in the FAT chain */
  public final int SectFatCount;

  /** First SECT in the directory chain */
  public final int SectDirStart;

  /** Maximum size for a mini stream */
  public final int MiniSectorCutoff;

  /** First SECT in the MiniFAT chain */
  public final int SectMiniFatStart;

  /** Number of SECTs in the MiniFAT chain */
  public final int SectMiniFatCount;

  /** First SECT in the DIFAT chain */
  public final int SectDifStart;

  /** Number of SECTs in the DIFAT chain */
  public final int SectDifCount;

  public CompoundFileHeader(SeekableByteChannel stream, BinaryReader reader) throws IOException {
    // magic 0xE11AB1A1E011CFD0
    if (reader.ReadInt64() != -2226271756974174256L)
      throw new InvalidDataException("Invalid format. Unknown magic value");

    ReadUtils.skip(stream, 18); // skip CLSID & Minor version

    int version = reader.ReadUInt16() & 0xFFFF;
    int byteOrder = reader.ReadUInt16() & 0xFFFF;

    if (byteOrder != 0xFFFE)
      throw new InvalidDataException("Invalid format. Only Little endian is expected");

    SectorShift = reader.ReadUInt16() & 0xFFFF;

    if (!((version == 3 && SectorShift == 9) || (version == 4 && SectorShift == 0xC)))
      throw new InvalidDataException("Invalid format. Version and sector size are incompatible");

    MiniSectorShift = reader.ReadUInt16() & 0xFFFF;

    if (MiniSectorShift != 6)
      throw new InvalidDataException("Invalid format. Mini Stream Sector Size must be equal 6");

    ReadUtils.skip(stream, 6); // skip "Reserved"

    SectDirCount = reader.ReadUInt32();
    SectFatCount = reader.ReadUInt32();
    SectDirStart = reader.ReadUInt32();
    ReadUtils.skip(stream, 4);
    MiniSectorCutoff = reader.ReadUInt32();
    SectMiniFatStart = reader.ReadUInt32();
    SectMiniFatCount = reader.ReadUInt32();
    SectDifStart = reader.ReadUInt32();
    SectDifCount = reader.ReadUInt32();
  }

  public int getSectorSize() {
    return 1 << SectorShift;
  }

  public int getMiniSectorSize() {
    return 1 << MiniSectorShift;
  }

  public long GetSectorOffset(int sect) {
    return Integer.toUnsignedLong(sect + 1) << SectorShift;
  }
}
