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
  private final SeekableByteChannel _stream;
  private final DataInfo _checkSum;
  private final DataInfo _imageDirectoryEntrySecurity;
  private final DataInfo _signData;
  private final DataInfo _dotnetMetadata;

  public int ImageDirectoryEntrySecurityOffset() {
    return _imageDirectoryEntrySecurity.Offset();
  }

  /** PE is .NET assembly */
  public boolean IsDotNet() {
    return !_dotnetMetadata.IsEmpty();
  }

  /** Initializes a new instance of the PeFile */
  public PeFile(SeekableByteChannel stream) {
    try {
      _stream = stream;
      ReadUtils.rewind(_stream);

      BinaryReader reader = new BinaryReader(_stream);

      if ((reader.ReadUInt16() & 0xFFFF) != 0x5A4D) // IMAGE_DOS_SIGNATURE
        throw new IllegalStateException("Unknown format");

      ReadUtils.seek(stream, 0x3C, SeekOrigin.Begin);
      int ntHeaderOffset = reader.ReadUInt32();
      _checkSum = new DataInfo(ntHeaderOffset + 0x58, 4);

      ReadUtils.seek(stream, Integer.toUnsignedLong(ntHeaderOffset), SeekOrigin.Begin);

      if (reader.ReadUInt32() != 0x00004550) // IMAGE_NT_SIGNATURE
        throw new IllegalStateException("Unknown format");

      ReadUtils.seek(stream, 0x12, SeekOrigin.Current); // IMAGE_FILE_HEADER::Characteristics

      int characteristics = reader.ReadUInt16() & 0x2002;
      // IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL
      if (characteristics != 0x2002 && characteristics != 0x0002)
        throw new IllegalStateException("Unknown format");

      int magic = reader.ReadUInt16() & 0xFFFF; // IMAGE_OPTIONAL_HEADER32::Magic / IMAGE_OPTIONAL_HEADER64::Magic
      if (magic == 0x10b) {
        ReadUtils.seek(stream, 0x60L - 2, SeekOrigin.Current); // Skip IMAGE_OPTIONAL_HEADER32 to DataDirectory
      } else if (magic == 0x20b) {
        ReadUtils.seek(stream, 0x70L - 2, SeekOrigin.Current); // Skip IMAGE_OPTIONAL_HEADER64 to DataDirectory
      } else {
        throw new IllegalStateException("Unknown format");
      }

      ReadUtils.seek(stream, 8L * 4L, SeekOrigin.Current); // DataDirectory + IMAGE_DIRECTORY_ENTRY_SECURITY
      _imageDirectoryEntrySecurity = new DataInfo((int) stream.position(), 8);
      int securityRva = reader.ReadUInt32();
      int securitySize = reader.ReadUInt32();
      _signData = new DataInfo(securityRva, securitySize);

      ReadUtils.seek(stream, 8L * 9L, SeekOrigin.Current); // DataDirectory + IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
      int dotnetMetadataRva = reader.ReadUInt32();
      int dotnetMetadataSize = reader.ReadUInt32();
      _dotnetMetadata = new DataInfo(dotnetMetadataRva, dotnetMetadataSize);
    } catch (IOException e) {
      throw new IllegalStateException("Unknown format", e);
    }
  }

  /** Retrieve the signature data from PE */
  public SignatureData GetSignatureData() {
    if (_signData.IsEmpty())
      return SignatureData.Empty;

    try {
      BinaryReader reader = new BinaryReader(ReadUtils.rewind(_stream));
      // jump to the sign data
      ReadUtils.seek(_stream, (long) _signData.Offset(), SeekOrigin.Begin);
      int dwLength = reader.ReadInt32();

      // skip wRevision, wCertificateType
      ReadUtils.seek(_stream, 4, SeekOrigin.Current);

      byte[] res = reader.ReadBytes(_signData.Size());

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

    long fileSize = _stream.size();

    // 1) Hash from start to checksum field (exclusive)
    long offset = 0;
    long count = _checkSum.Offset();
    hashRange(_stream, hash, offset, count);

    // 2) Skip checksum field, hash up to IMAGE_DIRECTORY_ENTRY_SECURITY (exclusive)
    offset = count + _checkSum.Size();
    count = _imageDirectoryEntrySecurity.Offset() - offset;
    hashRange(_stream, hash, offset, count);

    // 3) Skip IMAGE_DIRECTORY_ENTRY_SECURITY itself (8 bytes)
    offset = _imageDirectoryEntrySecurity.Offset() + _imageDirectoryEntrySecurity.Size();

    if (_signData.IsEmpty()) {
      // 4a) Not signed: hash to EOF
      count = fileSize - offset;
      hashRange(_stream, hash, offset, count);
    } else {
      // 4b) Signed: hash up to the start of signature data
      count = _signData.Offset() - offset;
      if (offset + count <= fileSize) {
        hashRange(_stream, hash, offset, count);
      }

      // 5) Jump over signature data and hash the rest to EOF
      offset = _signData.Offset() + _signData.Size();
      count = fileSize - offset;
      if (count > 0) {
        hashRange(_stream, hash, offset, count);
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
