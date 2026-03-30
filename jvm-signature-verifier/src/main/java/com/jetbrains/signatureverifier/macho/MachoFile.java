package com.jetbrains.signatureverifier.macho;

import com.jetbrains.signatureverifier.DataInfo;
import com.jetbrains.signatureverifier.InvalidDataException;
import com.jetbrains.signatureverifier.SignatureData;
import com.jetbrains.util.filetype.io.BinaryReader;
import com.jetbrains.util.filetype.io.ReadUtils;
import com.jetbrains.util.filetype.io.SeekOrigin;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MachoFile {
  private final SeekableByteChannel stream;
  private long magic = 0;
  public long magic() { return magic; }

  public boolean isLe32() { return magic == MachoConsts.MH_MAGIC; }
  public boolean isLe64() { return magic == MachoConsts.MH_MAGIC_64; }
  public boolean isBe32() { return magic == MachoConsts.MH_CIGAM; }
  public boolean isBe64() { return magic == MachoConsts.MH_CIGAM_64; }
  public boolean is32() { return isLe32() || isBe32(); }
  public boolean isBe() { return isBe32() || isBe64(); }

  private final DataInfo ncmdsOffset = new DataInfo(16, 8);
  private long ncmds = 0;
  private long sizeofcmds = 0;
  private long firstLoadCommandPosition = 0;

  /**
   * Initializes a new instance of the MachoFile
   *
   * @param stream An input stream
   * @throws InvalidDataException If the input stream does not contain MachO
   */
  public MachoFile(SeekableByteChannel stream) {
    this.stream = stream;
    setMagic();
  }

  private void setMagic() {
    try {
      BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));
      magic = Integer.toUnsignedLong(reader.readUInt32()); // mach_header::magic / mach_header64::magic

      if (!MachoUtils.isMacho(magic))
        throw new InvalidDataException("Unknown format");

      ReadUtils.seek(stream, (long) ncmdsOffset.getOffset(), SeekOrigin.Begin);
      ncmds = Integer.toUnsignedLong(reader.readUInt32Le(isBe())); // mach_header::ncmds / mach_header_64::ncmds
      sizeofcmds = Integer.toUnsignedLong(reader.readUInt32Le(isBe())); // mach_header::sizeofcmds / mach_header_64::sizeofcmds
      firstLoadCommandPosition = stream.position() + (is32() ? 4 : 8); // load_command[0]
    } catch (IOException e) {
      throw new InvalidDataException("Unknown format");
    }
  }

  public byte[] ComputeHash(String algName) throws Exception {
    List<DataInfo> excludeRanges = getHashExcludeRanges().getKey();
    boolean hasLcCodeSignature = getHashExcludeRanges().getValue();
    MessageDigest hash = MessageDigest.getInstance(algName);

    byte[] buffer = new byte[1024 * 1024];

    if (!excludeRanges.isEmpty()) {
      ReadUtils.rewind(stream);
      for (DataInfo dataInfo : excludeRanges) {
        long size = (long) dataInfo.getOffset() - stream.position();
        if (size > 0) {
          readAndHash(stream, hash, buffer, size);
        }
        // Skip excluded range
        ReadUtils.seek(stream, (long) dataInfo.getSize(), SeekOrigin.Current);
      }

      // Hash the rest to the end
      readToEndAndHash(stream, hash, buffer);

      // append zero-inset to the end of data
      if (!hasLcCodeSignature) {
        long filesize = stream.position();
        long zeroInsetSize = filesize % 16;
        if (zeroInsetSize > 0) {
          zeroInsetSize = 16 - zeroInsetSize;
          hash.update(new byte[(int) zeroInsetSize]);
        }
      }
    } else {
      ReadUtils.rewind(stream);
      readToEndAndHash(stream, hash, buffer);
    }
    return hash.digest();
  }

  private static void readAndHash(SeekableByteChannel stream, MessageDigest hash, byte[] buffer, long count) throws IOException {
    long remaining = count;
    while (remaining > 0) {
      int toRead = (int) Math.min(remaining, buffer.length);
      ByteBuffer byteBuffer = ByteBuffer.wrap(buffer, 0, toRead);
      int bytesRead = stream.read(byteBuffer);
      if (bytesRead <= 0) break;
      hash.update(buffer, 0, bytesRead);
      remaining -= bytesRead;
    }
  }

  private static void readToEndAndHash(SeekableByteChannel stream, MessageDigest hash, byte[] buffer) throws IOException {
    while (true) {
      ByteBuffer byteBuffer = ByteBuffer.wrap(buffer);
      int bytesRead = stream.read(byteBuffer);
      if (bytesRead <= 0) break;
      hash.update(buffer, 0, bytesRead);
    }
  }

  private java.util.AbstractMap.SimpleImmutableEntry<List<DataInfo>, Boolean> getHashExcludeRanges() throws IOException {
    List<DataInfo> excludeRanges = new ArrayList<>(Collections.singletonList(ncmdsOffset));
    BinaryReader reader = new BinaryReader(stream);
    ReadUtils.seek(stream, firstLoadCommandPosition, SeekOrigin.Begin); // load_command[0]

    boolean hasLcCodeSignature = false;
    long _ncmds = ncmds;
    while (_ncmds-- > 0) {
      long cmpPosition = stream.position();
      int cmd = reader.readUInt32Le(isBe32() || isBe64());     // load_command::cmd
      int cmdsize = reader.readUInt32Le(isBe32() || isBe64()); // load_command::cmdsize

      if (cmd == MachoConsts.LC_SEGMENT || cmd == MachoConsts.LC_SEGMENT_64) {
        String segname = reader.readString(10);
        if ("__LINKEDIT".equals(segname)) {
          ReadUtils.seek(stream, 6, SeekOrigin.Current); // skip to end of segname (16 bytes total)
          ReadUtils.seek(stream, is32() ? 4 : 8, SeekOrigin.Current); // skip vmaddr

          DataInfo vmsizeOffset = new DataInfo((int) stream.position(), is32() ? 4 : 8);
          excludeRanges.add(vmsizeOffset);

          ReadUtils.seek(stream, (long) (is32() ? 4 : 8) * 2, SeekOrigin.Current); // skip vmsize and fileoff

          DataInfo filesizeOffset = new DataInfo((int) stream.position(), is32() ? 4 : 8);
          excludeRanges.add(filesizeOffset);
        }
      } else if (cmd == MachoConsts.LC_CODE_SIGNATURE) {
        DataInfo lcCodeSignatureOffset = new DataInfo((int) cmpPosition, cmdsize);
        excludeRanges.add(lcCodeSignatureOffset);
        DataInfo lcCodeSignatureDataOffset = new DataInfo(
          reader.readUInt32Le(isBe()),  // load_command::dataoff
          reader.readUInt32Le(isBe())   // load_command::datasize
        );
        excludeRanges.add(lcCodeSignatureDataOffset);
        hasLcCodeSignature = true;
      }

      long remaining = Integer.toUnsignedLong(cmdsize) - (stream.position() - cmpPosition);
      ReadUtils.seek(stream, remaining, SeekOrigin.Current);
    }

    if (!hasLcCodeSignature) {
      // exclude the LC_CODE_SIGNATURE zero placeholder from hashing
      excludeRanges.add(new DataInfo((int) (firstLoadCommandPosition + sizeofcmds), 16));
    }
    return new java.util.AbstractMap.SimpleImmutableEntry<>(excludeRanges, hasLcCodeSignature);
  }

  /**
   * Retrieve the signature data from MachO
   *
   * @throws InvalidDataException If the input stream does not correspond to MachO format or signature data is malformed
   */
  public SignatureData getSignatureData() {
    try {
      return getMachoSignatureData();
    } catch (IOException ex) {
      throw new InvalidDataException("Invalid format");
    }
  }

  private SignatureData getMachoSignatureData() throws IOException {
    // Note: See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h
    byte[] signedData = null;
    byte[] cmsData = null;
    BinaryReader reader = new BinaryReader(stream);
    ReadUtils.seek(stream, firstLoadCommandPosition, SeekOrigin.Begin); // load_command[0]

    long _ncmds = ncmds;
    while (_ncmds-- > 0) {
      int cmd = reader.readUInt32Le(isBe32() || isBe64());     // load_command::cmd
      int cmdsize = reader.readUInt32Le(isBe32() || isBe64()); // load_command::cmdsize

      if (cmd == MachoConsts.LC_CODE_SIGNATURE) {
        int dataoff = reader.readUInt32Le(isBe32() || isBe64()); // load_command::dataoff
        ReadUtils.seek(stream, Integer.toUnsignedLong(dataoff), SeekOrigin.Begin);
        long CS_SuperBlob_start = stream.position();
        ReadUtils.seek(stream, 8, SeekOrigin.Current);
        int CS_SuperBlob_count = reader.readUInt32Le(true);

        while (CS_SuperBlob_count-- > 0) {
          int CS_BlobIndex_type = reader.readUInt32Le(true);
          int CS_BlobIndex_offset = reader.readUInt32Le(true);
          long position = stream.position();

          if (CS_BlobIndex_type == MachoConsts.CSSLOT_CODEDIRECTORY) {
            ReadUtils.seek(stream, CS_SuperBlob_start, SeekOrigin.Begin);
            ReadUtils.seek(stream, Integer.toUnsignedLong(CS_BlobIndex_offset), SeekOrigin.Current);
            signedData = MachoUtils.ReadCodeDirectoryBlob(reader);
            ReadUtils.seek(stream, position, SeekOrigin.Begin);
          } else if (CS_BlobIndex_type == MachoConsts.CSSLOT_CMS_SIGNATURE) {
            ReadUtils.seek(stream, CS_SuperBlob_start, SeekOrigin.Begin);
            ReadUtils.seek(stream, Integer.toUnsignedLong(CS_BlobIndex_offset), SeekOrigin.Current);
            cmsData = MachoUtils.ReadBlob(reader);
            ReadUtils.seek(stream, position, SeekOrigin.Begin);
          }
        }
      }
      ReadUtils.seek(stream, Integer.toUnsignedLong(cmdsize) - 8L, SeekOrigin.Current);
    }
    return new SignatureData(signedData, cmsData);
  }
}
