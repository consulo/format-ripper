package com.jetbrains.signatureverifier;

import com.jetbrains.util.filetype.io.BinaryReader;
import com.jetbrains.util.filetype.io.ReadUtils;
import com.jetbrains.util.filetype.io.SeekOrigin;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Portable Executable file from the specified channel */
public class PeFile {
  private final SeekableByteChannel stream;
  private final DataInfo checkSum;
  private final DataInfo imageDirectoryEntrySecurity;
  private final DataInfo signData;
  private final DataInfo dotnetMetadata;

  public int imageDirectoryEntrySecurityOffset() {
    return imageDirectoryEntrySecurity.getOffset();
  }

  /** PE is .NET assembly */
  public boolean isDotNet() {
    return !dotnetMetadata.isEmpty();
  }

  /** Initializes a new instance of the PeFile */
  public PeFile(SeekableByteChannel stream) {
    try {
      this.stream = stream;
      ReadUtils.rewind(stream);

      BinaryReader reader = new BinaryReader(stream);

      if ((reader.readUInt16() & 0xFFFF) != 0x5A4D) // IMAGE_DOS_SIGNATURE
        throw new IllegalStateException("Unknown format");

      ReadUtils.seek(stream, 0x3C, SeekOrigin.Begin);
      int ntHeaderOffset = reader.readUInt32();
      checkSum = new DataInfo(ntHeaderOffset + 0x58, 4);

      ReadUtils.seek(stream, Integer.toUnsignedLong(ntHeaderOffset), SeekOrigin.Begin);

      if (reader.readUInt32() != 0x00004550) // IMAGE_NT_SIGNATURE
        throw new IllegalStateException("Unknown format");

      ReadUtils.seek(stream, 0x12, SeekOrigin.Current); // IMAGE_FILE_HEADER::Characteristics

      int characteristics = reader.readUInt16() & 0x2002;
      // IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL
      if (characteristics != 0x2002 && characteristics != 0x0002)
        throw new IllegalStateException("Unknown format");

      int magic = reader.readUInt16() & 0xFFFF; // IMAGE_OPTIONAL_HEADER32::Magic / IMAGE_OPTIONAL_HEADER64::Magic
      if (magic == 0x10b) {
        ReadUtils.seek(stream, 0x60L - 2, SeekOrigin.Current); // Skip IMAGE_OPTIONAL_HEADER32 to DataDirectory
      } else if (magic == 0x20b) {
        ReadUtils.seek(stream, 0x70L - 2, SeekOrigin.Current); // Skip IMAGE_OPTIONAL_HEADER64 to DataDirectory
      } else {
        throw new IllegalStateException("Unknown format");
      }

      ReadUtils.seek(stream, 8L * 4L, SeekOrigin.Current); // DataDirectory + IMAGE_DIRECTORY_ENTRY_SECURITY
      imageDirectoryEntrySecurity = new DataInfo((int) stream.position(), 8);
      int securityRva = reader.readUInt32();
      int securitySize = reader.readUInt32();
      signData = new DataInfo(securityRva, securitySize);

      ReadUtils.seek(stream, 8L * 9L, SeekOrigin.Current); // DataDirectory + IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
      int dotnetMetadataRva = reader.readUInt32();
      int dotnetMetadataSize = reader.readUInt32();
      dotnetMetadata = new DataInfo(dotnetMetadataRva, dotnetMetadataSize);
    } catch (IOException e) {
      throw new IllegalStateException("Unknown format", e);
    }
  }

  /** Retrieve the signature data from PE */
  public SignatureData getSignatureData() {
    if (signData.isEmpty())
      return SignatureData.Empty;

    try {
      BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));
      // jump to the sign data
      ReadUtils.seek(stream, (long) signData.getOffset(), SeekOrigin.Begin);
      int dwLength = reader.readInt32();

      // skip wRevision, wCertificateType
      ReadUtils.seek(stream, 4, SeekOrigin.Current);

      byte[] res = reader.readBytes(signData.getSize());

      // need more data
      if (res.length < dwLength - 8)
        return SignatureData.Empty;

      return new SignatureData(null, res);
    } catch (IOException ex) {
      // need more data
      return SignatureData.Empty;
    }
  }

  /**
   * Compute hash of PE structure
   *
   * @param algName Name of the hashing algorithm
   */
  public byte[] ComputeHash(String algName) throws NoSuchAlgorithmException, IOException {
    MessageDigest hash = MessageDigest.getInstance(algName);

    long fileSize = stream.size();

    // 1) Hash from start to checksum field (exclusive)
    long offset = 0;
    long count = checkSum.getOffset();
    hashRange(stream, hash, offset, count);

    // 2) Skip checksum field, hash up to IMAGE_DIRECTORY_ENTRY_SECURITY (exclusive)
    offset = count + checkSum.getSize();
    count = imageDirectoryEntrySecurity.getOffset() - offset;
    hashRange(stream, hash, offset, count);

    // 3) Skip IMAGE_DIRECTORY_ENTRY_SECURITY itself (8 bytes)
    offset = imageDirectoryEntrySecurity.getOffset() + imageDirectoryEntrySecurity.getSize();

    if (signData.isEmpty()) {
      // 4a) Not signed: hash to EOF
      count = fileSize - offset;
      hashRange(stream, hash, offset, count);
    } else {
      // 4b) Signed: hash up to the start of signature data
      count = signData.getOffset() - offset;
      if (offset + count <= fileSize) {
        hashRange(stream, hash, offset, count);
      }

      // 5) Jump over signature data and hash the rest to EOF
      offset = signData.getOffset() + signData.getSize();
      count = fileSize - offset;
      if (count > 0) {
        hashRange(stream, hash, offset, count);
      }
    }

    return hash.digest();
  }

  private static void hashRange(SeekableByteChannel stream, MessageDigest hash, long startOffset, long length) throws IOException {
    if (length <= 0L) return;
    long fileSize = stream.size();
    long safeStart = Math.max(0L, Math.min(startOffset, fileSize));
    long maxLen = Math.max(0L, fileSize - safeStart);
    long safeLen = Math.min(length, maxLen);
    if (safeLen <= 0L) return;

    byte[] buffer = new byte[1024 * 1024]; // 1MB chunks
    long remaining = safeLen;
    ReadUtils.seek(stream, safeStart, SeekOrigin.Begin);
    while (remaining > 0) {
      int toRead = (int) Math.min(remaining, buffer.length);
      int bytesRead = stream.read(ByteBuffer.wrap(buffer, 0, toRead));
      if (bytesRead <= 0) break;
      hash.update(buffer, 0, bytesRead);
      remaining -= bytesRead;
    }
  }
}
