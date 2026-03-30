package com.jetbrains.signatureverifier.cf;

import com.jetbrains.signatureverifier.InvalidDataException;
import com.jetbrains.util.filetype.io.BinaryReader;
import com.jetbrains.util.filetype.io.ReadUtils;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

// Note: Object Linking and Embedding (OLE) Compound File (CF) (i.e., OLECF) or Compound Binary File format by Microsoft
public class CompoundFile {
  private static final int DIRECTORY_ENTRY_SIZE = 0x80;

  private final SeekableByteChannel stream;
  private final CompoundFileHeader header;
  private final List<Integer> sectFat;
  private final List<Integer> fat;
  private final List<Integer> miniFat;

  public CompoundFile(SeekableByteChannel stream) throws IOException {
    this.stream = stream;
    BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));
    header = new CompoundFileHeader(stream, reader);
    sectFat = readSectFat(reader);
    fat = readFat(reader);
    miniFat = readMiniFat(reader);
  }

  public byte[] getStreamData(byte[] entryName) throws IOException {
    BinaryReader reader = new BinaryReader(stream);
    DirectoryEntry dirEntry = findStreamByName(reader, entryName);
    if (dirEntry != null)
      return readStreamData(reader, dirEntry);
    return null;
  }

  public byte[] getStreamData(DirectoryEntry entry) throws IOException {
    BinaryReader reader = new BinaryReader(stream);
    return readStreamData(reader, entry);
  }

  public List<DirectoryEntry> getStreamDirectoryEntries() throws IOException {
    BinaryReader reader = new BinaryReader(stream);
    List<DirectoryEntry> res = new ArrayList<>();
    int nextSect = header.sectDirStart;

    while (Integer.toUnsignedLong(nextSect) != SpecialSectors.ENDOFCHAIN) {
      ReadUtils.jump(stream, header.getSectorOffset(nextSect));

      int count = header.getSectorSize() / DIRECTORY_ENTRY_SIZE;
      for (int dirIndex = 0; dirIndex < count; dirIndex++) {
        DirectoryEntry dirEntry = readDirectoryEntry(reader);
        if (dirEntry.entryType == DirectoryEntryType.STGTY_STREAM)
          res.add(dirEntry);
      }
      nextSect = fat.get(nextSect);
    }
    return res;
  }

  public byte[] getRootDirectoryClsid() throws IOException {
    BinaryReader reader = new BinaryReader(stream);
    DirectoryEntry root = findRootDirectoryEntry(reader);
    return root != null ? root.clsid : null;
  }

  private List<Integer> readFat(BinaryReader reader) throws IOException {
    List<Integer> res = new ArrayList<>();
    for (int sect : sectFat) {
      ReadUtils.jump(stream, header.getSectorOffset(sect));
      int count = header.getSectorSize() >> 2;
      for (int j = 0; j < count; j++) {
        res.add(reader.readUInt32());
      }
    }
    return res;
  }

  private List<Integer> readSectFat(BinaryReader reader) throws IOException {
    List<Integer> res = new ArrayList<>();

    for (int i = 0; i < 109; i++) {
      int sector = reader.readUInt32();
      if (Integer.toUnsignedLong(sector) == SpecialSectors.FREESECT)
        break;
      res.add(sector);
    }

    int nextSect = header.sectDifStart;
    int difatSectorsCount = (header.getSectorSize() >> 2) - 1;

    while (Integer.toUnsignedLong(nextSect) != SpecialSectors.ENDOFCHAIN) {
      ReadUtils.jump(stream, header.getSectorOffset(nextSect));

      for (int i = 0; i < difatSectorsCount; i++) {
        int sector = reader.readUInt32();
        long sectorUnsigned = Integer.toUnsignedLong(sector);
        if (sectorUnsigned == SpecialSectors.FREESECT || sectorUnsigned == SpecialSectors.ENDOFCHAIN) {
          return res;
        }
        res.add(sector);
      }
      // next sector in the difat chain
      nextSect = reader.readUInt32();
    }
    return res;
  }

  private DirectoryEntry findRootDirectoryEntry(BinaryReader reader) throws IOException {
    if (Integer.toUnsignedLong(header.sectDirStart) != SpecialSectors.ENDOFCHAIN) {
      ReadUtils.jump(stream, header.getSectorOffset(header.sectDirStart));
      return readDirectoryEntry(reader);
    }
    return null;
  }

  private DirectoryEntry findStreamByName(BinaryReader reader, byte[] streamName) throws IOException {
    int nextSect = header.sectDirStart;

    while (Integer.toUnsignedLong(nextSect) != SpecialSectors.ENDOFCHAIN) {
      ReadUtils.jump(stream, header.getSectorOffset(nextSect));

      int count = header.getSectorSize() / DIRECTORY_ENTRY_SIZE;
      for (int dirIndex = 0; dirIndex < count; dirIndex++) {
        DirectoryEntry dirEntry = readDirectoryEntry(reader);
        if (Arrays.equals(streamName, dirEntry.name) && dirEntry.entryType == DirectoryEntryType.STGTY_STREAM)
          return dirEntry;
      }
      nextSect = fat.get(nextSect);
    }
    return null;
  }

  private byte[] readStreamData(BinaryReader reader, DirectoryEntry dirEntry) throws IOException {
    if (Integer.toUnsignedLong(dirEntry.sizeLow) <= Integer.toUnsignedLong(header.miniSectorCutoff)) {
      DirectoryEntry rootDirectoryEntry = findRootDirectoryEntry(reader);

      if (rootDirectoryEntry == null || rootDirectoryEntry.entryType != DirectoryEntryType.STGTY_ROOT)
        throw new InvalidDataException("Invalid format. Root directory entry not found");

      int miniStreamStartSector = rootDirectoryEntry.startSect;
      long miniStreamSectorOffset = header.getSectorOffset(miniStreamStartSector);
      return readStreamData(
        reader,
        miniFat,
        dirEntry.sizeLow,
        dirEntry.startSect,
        header.getMiniSectorSize(),
        (int) miniStreamSectorOffset
      );
    }
    return readStreamData(reader, fat, dirEntry.sizeLow, dirEntry.startSect, header.getSectorSize(), 0);
  }

  private byte[] readStreamData(
    BinaryReader reader,
    List<Integer> fat,
    int size,
    int startSect,
    int sectorSize,
    int baseOffset
  ) throws IOException {
    byte[] res = new byte[size];
    int read = 0;
    int nextSect = startSect;

    while (Integer.toUnsignedLong(nextSect) != SpecialSectors.ENDOFCHAIN) {
      long streamOffset;

      if (sectorSize == header.getMiniSectorSize()) {
        streamOffset = Integer.toUnsignedLong(baseOffset) + (Integer.toUnsignedLong(nextSect) << header.miniSectorShift);
      } else {
        streamOffset = header.getSectorOffset(nextSect);
      }

      ReadUtils.jump(stream, streamOffset);
      int toRead = Math.min(size - read, sectorSize);
      byte[] data = reader.readBytes(toRead);
      System.arraycopy(data, 0, res, read, data.length);
      read += data.length;
      nextSect = fat.get(nextSect);
    }
    return res;
  }

  private List<Integer> readMiniFat(BinaryReader reader) throws IOException {
    List<Integer> miniFat = new ArrayList<>();
    int nextSect = header.sectMiniFatStart;

    while (Integer.toUnsignedLong(nextSect) != SpecialSectors.ENDOFCHAIN) {
      ReadUtils.jump(stream, header.getSectorOffset(nextSect));

      int count = header.getSectorSize() >> 2;
      for (int j = 0; j < count; j++) {
        miniFat.add(reader.readUInt32());
      }

      nextSect = fat.get(nextSect);
    }
    return miniFat;
  }

  private DirectoryEntry readDirectoryEntry(BinaryReader reader) throws IOException {
    return new DirectoryEntry(stream, reader);
  }
}
