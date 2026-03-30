package com.jetbrains.signatureverifier.cf;

import com.jetbrains.signatureverifier.SignatureData;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * MS Windows Installer compound file
 */
public class MsiFile {
  private final CompoundFile _cf;

  // \u0005DigitalSignature
  private static final byte[] DIGITAL_SIGNATURE_ENTRY_NAME = {
    0x5, 0x0, 0x44, 0x00, 0x69, 0x00, 0x67, 0x00, 0x69, 0x00, 0x74, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x53,
    0x00, 0x69, 0x00, 0x67, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x74, 0x00, 0x75, 0x00, 0x72, 0x00, 0x65, 0x00
  };

  // \u0005MsiDigitalSignatureEx
  private static final byte[] MSI_DIGITAL_SIGNATURE_EX_ENTRY_NAME = {
    0x5, 0x0, 0x4D, 0x00, 0x73, 0x00, 0x69, 0x00, 0x44, 0x00, 0x69, 0x00, 0x67, 0x00, 0x69, 0x00, 0x74, 0x00, 0x61,
    0x00, 0x6C, 0x00, 0x53, 0x00, 0x69, 0x00, 0x67, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x74, 0x00, 0x75, 0x00, 0x72, 0x00,
    0x65, 0x00, 0x45, 0x00, 0x78, 0x00
  };

  /**
   * Initializes a new instance of the MsiFile
   *
   * @param stream An input stream
   * @throws InvalidDataException If the input stream contains a compound file with wrong structure
   */
  public MsiFile(SeekableByteChannel stream) throws IOException {
    _cf = new CompoundFile(stream);
  }

  /**
   * Retrieve the signature data from MSI
   */
  public SignatureData GetSignatureData() throws IOException {
    byte[] data = _cf.GetStreamData(DIGITAL_SIGNATURE_ENTRY_NAME);
    if (data == null)
      return SignatureData.Empty;
    return new SignatureData(null, data);
  }

  /**
   * Compute hash of MSI structure
   *
   * @param algName                        Name of the hashing algorithm
   * @param skipMsiDigitalSignatureExEntry Skip \u0005MsiDigitalSignatureEx entry data when hashing
   */
  public byte[] ComputeHash(String algName, boolean skipMsiDigitalSignatureExEntry) throws IOException, NoSuchAlgorithmException {
    List<DirectoryEntry> entries = _cf.GetStreamDirectoryEntries();
    entries.sort(this::compareDirectoryEntries);

    MessageDigest hash = MessageDigest.getInstance(algName);

    for (DirectoryEntry entry : entries) {
      if (Arrays.equals(entry.Name, DIGITAL_SIGNATURE_ENTRY_NAME))
        continue;

      if (skipMsiDigitalSignatureExEntry && Arrays.equals(entry.Name, MSI_DIGITAL_SIGNATURE_EX_ENTRY_NAME))
        continue;

      byte[] data = _cf.GetStreamData(entry);
      hash.update(data);
    }

    byte[] rootClsid = _cf.GetRootDirectoryClsid();
    if (rootClsid != null)
      hash.update(rootClsid);

    return hash.digest();
  }

  private int compareDirectoryEntries(DirectoryEntry e1, DirectoryEntry e2) {
    byte[] a = e1.Name;
    byte[] b = e2.Name;
    int size = Math.min(a.length, b.length);

    for (int i = 0; i < size; i++)
      if (a[i] != b[i])
        return (a[i] & 0xFF) - (b[i] & 0xFF);

    return a.length - b.length;
  }
}
