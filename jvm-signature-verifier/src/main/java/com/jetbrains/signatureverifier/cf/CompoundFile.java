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

  private final SeekableByteChannel _stream;
  private final CompoundFileHeader _header;
  private final List<Integer> _sectFat;
  private final List<Integer> _fat;
  private final List<Integer> _miniFat;

  public CompoundFile(SeekableByteChannel stream) throws IOException {
    _stream = stream;
    BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));
    _header = new CompoundFileHeader(_stream, reader);
    _sectFat = readSectFat(reader);
    _fat = readFat(reader);
    _miniFat = readMiniFat(reader);
  }

  public byte[] GetStreamData(byte[] entryName) throws IOException {
    BinaryReader reader = new BinaryReader(_stream);
    DirectoryEntry dirEntry = findStreamByName(reader, entryName);
    if (dirEntry != null)
      return readStreamData(reader, dirEntry);
    return null;
  }

  public byte[] GetStreamData(DirectoryEntry entry) throws IOException {
    BinaryReader reader = new BinaryReader(_stream);
    return readStreamData(reader, entry);
  }

  public List<DirectoryEntry> GetStreamDirectoryEntries() throws IOException {
    BinaryReader reader = new BinaryReader(_stream);
    List<DirectoryEntry> res = new ArrayList<>();
    int nextSect = _header.SectDirStart;

    while (Integer.toUnsignedLong(nextSect) != SpecialSectors.ENDOFCHAIN) {
      ReadUtils.jump(_stream, _header.GetSectorOffset(nextSect));

      int count = _header.getSectorSize() / DIRECTORY_ENTRY_SIZE;
      for (int dirIndex = 0; dirIndex < count; dirIndex++) {
        DirectoryEntry dirEntry = readDirectoryEntry(reader);
        if (dirEntry.EntryType == DirectoryEntryType.STGTY_STREAM)
          res.add(dirEntry);
      }
      nextSect = _fat.get(nextSect);
    }
    return res;
  }

  public byte[] GetRootDirectoryClsid() throws IOException {
    BinaryReader reader = new BinaryReader(_stream);
    DirectoryEntry root = findRootDirectoryEntry(reader);
    return root != null ? root.Clsid : null;
  }

  private List<Integer> readFat(BinaryReader reader) throws IOException {
    List<Integer> res = new ArrayList<>();
    for (int sect : _sectFat) {
      ReadUtils.jump(_stream, _header.GetSectorOffset(sect));
      int count = _header.getSectorSize() >> 2;
      for (int j = 0; j < count; j++) {
        res.add(reader.ReadUInt32());
      }
    }
    return res;
  }

  private List<Integer> readSectFat(BinaryReader reader) throws IOException {
    List<Integer> res = new ArrayList<>();

    for (int i = 0; i < 109; i++) {
      int sector = reader.ReadUInt32();
      if (Integer.toUnsignedLong(sector) == SpecialSectors.FREESECT)
        break;
      res.add(sector);
    }

    int nextSect = _header.SectDifStart;
    int difatSectorsCount = (_header.getSectorSize() >> 2) - 1;

    while (Integer.toUnsignedLong(nextSect) != SpecialSectors.ENDOFCHAIN) {
      ReadUtils.jump(_stream, _header.GetSectorOffset(nextSect));

      for (int i = 0; i < difatSectorsCount; i++) {
        int sector = reader.ReadUInt32();
        long sectorUnsigned = Integer.toUnsignedLong(sector);
        if (sectorUnsigned == SpecialSectors.FREESECT || sectorUnsigned == SpecialSectors.ENDOFCHAIN) {
          return res;
        }
        res.add(sector);
      }
      // next sector in the difat chain
      nextSect = reader.ReadUInt32();
    }
    return res;
  }

  private DirectoryEntry findRootDirectoryEntry(BinaryReader reader) throws IOException {
    if (Integer.toUnsignedLong(_header.SectDirStart) != SpecialSectors.ENDOFCHAIN) {
      ReadUtils.jump(_stream, _header.GetSectorOffset(_header.SectDirStart));
      return readDirectoryEntry(reader);
    }
    return null;
  }

  private DirectoryEntry findStreamByName(BinaryReader reader, byte[] streamName) throws IOException {
    int nextSect = _header.SectDirStart;

    while (Integer.toUnsignedLong(nextSect) != SpecialSectors.ENDOFCHAIN) {
      ReadUtils.jump(_stream, _header.GetSectorOffset(nextSect));

      int count = _header.getSectorSize() / DIRECTORY_ENTRY_SIZE;
      for (int dirIndex = 0; dirIndex < count; dirIndex++) {
        DirectoryEntry dirEntry = readDirectoryEntry(reader);
        if (Arrays.equals(streamName, dirEntry.Name) && dirEntry.EntryType == DirectoryEntryType.STGTY_STREAM)
          return dirEntry;
      }
      nextSect = _fat.get(nextSect);
    }
    return null;
  }

  private byte[] readStreamData(BinaryReader reader, DirectoryEntry dirEntry) throws IOException {
    if (Integer.toUnsignedLong(dirEntry.SizeLow) <= Integer.toUnsignedLong(_header.MiniSectorCutoff)) {
      DirectoryEntry rootDirectoryEntry = findRootDirectoryEntry(reader);

      if (rootDirectoryEntry == null || rootDirectoryEntry.EntryType != DirectoryEntryType.STGTY_ROOT)
        throw new InvalidDataException("Invalid format. Root directory entry not found");

      int miniStreamStartSector = rootDirectoryEntry.StartSect;
      long miniStreamSectorOffset = _header.GetSectorOffset(miniStreamStartSector);
      return readStreamData(
        reader,
        _miniFat,
        dirEntry.SizeLow,
        dirEntry.StartSect,
        _header.getMiniSectorSize(),
        (int) miniStreamSectorOffset
      );
    }
    return readStreamData(reader, _fat, dirEntry.SizeLow, dirEntry.StartSect, _header.getSectorSize(), 0);
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

      if (sectorSize == _header.getMiniSectorSize()) {
        streamOffset = Integer.toUnsignedLong(baseOffset) + (Integer.toUnsignedLong(nextSect) << _header.MiniSectorShift);
      } else {
        streamOffset = _header.GetSectorOffset(nextSect);
      }

      ReadUtils.jump(_stream, streamOffset);
      int toRead = Math.min(size - read, sectorSize);
      byte[] data = reader.ReadBytes(toRead);
      System.arraycopy(data, 0, res, read, data.length);
      read += data.length;
      nextSect = fat.get(nextSect);
    }
    return res;
  }

  private List<Integer> readMiniFat(BinaryReader reader) throws IOException {
    List<Integer> miniFat = new ArrayList<>();
    int nextSect = _header.SectMiniFatStart;

    while (Integer.toUnsignedLong(nextSect) != SpecialSectors.ENDOFCHAIN) {
      ReadUtils.jump(_stream, _header.GetSectorOffset(nextSect));

      int count = _header.getSectorSize() >> 2;
      for (int j = 0; j < count; j++) {
        miniFat.add(reader.ReadUInt32());
      }

      nextSect = _fat.get(nextSect);
    }
    return miniFat;
  }

  private DirectoryEntry readDirectoryEntry(BinaryReader reader) throws IOException {
    return new DirectoryEntry(_stream, reader);
  }
}
