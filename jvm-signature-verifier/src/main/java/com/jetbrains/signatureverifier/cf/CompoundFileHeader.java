package com.jetbrains.signatureverifier.cf;

import com.jetbrains.signatureverifier.InvalidDataException;
import com.jetbrains.util.filetype.io.BinaryReader;
import com.jetbrains.util.filetype.io.ReadUtils;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;

public class CompoundFileHeader {
  /** Size of sectors in power-of-two */
  public final int sectorShift;

  /** Size of mini-sectors in power-of-two, typically 6 indicating 64-byte mini-sectors */
  public final int miniSectorShift;

  /** Number of SECTs in directory chain for 4 KB sectors, must be zero for 512-byte sectors */
  public final int sectDirCount;

  /** Number of SECTs in the FAT chain */
  public final int sectFatCount;

  /** First SECT in the directory chain */
  public final int sectDirStart;

  /** Maximum size for a mini stream */
  public final int miniSectorCutoff;

  /** First SECT in the MiniFAT chain */
  public final int sectMiniFatStart;

  /** Number of SECTs in the MiniFAT chain */
  public final int sectMiniFatCount;

  /** First SECT in the DIFAT chain */
  public final int sectDifStart;

  /** Number of SECTs in the DIFAT chain */
  public final int sectDifCount;

  public CompoundFileHeader(SeekableByteChannel stream, BinaryReader reader) throws IOException {
    // magic 0xE11AB1A1E011CFD0
    if (reader.readInt64() != -2226271756974174256L)
      throw new InvalidDataException("Invalid format. Unknown magic value");

    ReadUtils.skip(stream, 18); // skip CLSID & Minor version

    int version = reader.readUInt16() & 0xFFFF;
    int byteOrder = reader.readUInt16() & 0xFFFF;

    if (byteOrder != 0xFFFE)
      throw new InvalidDataException("Invalid format. Only Little endian is expected");

    sectorShift = reader.readUInt16() & 0xFFFF;

    if (!((version == 3 && sectorShift == 9) || (version == 4 && sectorShift == 0xC)))
      throw new InvalidDataException("Invalid format. Version and sector size are incompatible");

    miniSectorShift = reader.readUInt16() & 0xFFFF;

    if (miniSectorShift != 6)
      throw new InvalidDataException("Invalid format. Mini Stream Sector Size must be equal 6");

    ReadUtils.skip(stream, 6); // skip "Reserved"

    sectDirCount = reader.readUInt32();
    sectFatCount = reader.readUInt32();
    sectDirStart = reader.readUInt32();
    ReadUtils.skip(stream, 4);
    miniSectorCutoff = reader.readUInt32();
    sectMiniFatStart = reader.readUInt32();
    sectMiniFatCount = reader.readUInt32();
    sectDifStart = reader.readUInt32();
    sectDifCount = reader.readUInt32();
  }

  public int getSectorSize() {
    return 1 << sectorShift;
  }

  public int getMiniSectorSize() {
    return 1 << miniSectorShift;
  }

  public long getSectorOffset(int sect) {
    return Integer.toUnsignedLong(sect + 1) << sectorShift;
  }
}
