package com.jetbrains.signatureverifier.cf;

import com.jetbrains.util.filetype.io.BinaryReader;
import com.jetbrains.util.filetype.io.ReadUtils;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;

public class DirectoryEntry {
  public final byte[] Name;
  public final byte EntryType;
  public final byte[] Clsid;
  public final int StartSect;
  public final int SizeLow;
  public final int SizeHigh;

  public DirectoryEntry(SeekableByteChannel stream, BinaryReader reader) throws IOException {
    byte[] _name = reader.ReadBytes(64);
    short _nameLen = reader.ReadUInt16();

    if ((_nameLen & 0xFFFF) > 2) {
      int len = (_nameLen & 0xFFFF) - 2;
      Name = new byte[len];
      System.arraycopy(_name, 0, Name, 0, len);
    } else {
      Name = new byte[0];
    }

    EntryType = reader.ReadByte();

    if (EntryType == DirectoryEntryType.STGTY_ROOT) {
      ReadUtils.skip(stream, 13);
      Clsid = reader.ReadBytes(16);
      ReadUtils.skip(stream, 20);
    } else {
      Clsid = null;
      ReadUtils.skip(stream, 49);
    }

    StartSect = reader.ReadUInt32();
    SizeLow = reader.ReadUInt32();
    SizeHigh = reader.ReadUInt32();
  }
}
