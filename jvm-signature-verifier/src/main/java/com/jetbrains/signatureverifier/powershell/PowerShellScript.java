package com.jetbrains.signatureverifier.powershell;

import org.apache.commons.io.ByteOrderMark;
import org.apache.commons.io.input.BOMInputStream;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Based on https://github.com/ebourg/jsign/blob/master/jsign-core/src/main/java/net/jsign/script/PowerShellScript.java
 */
public class PowerShellScript {
  public static final String SIGNATURE_START = "# SIG # Begin signature block";
  public static final String SIGNATURE_END = "# SIG # End signature block";

  private static final String EOL = "\\r\\n";
  private static final String EOL_OPTIONAL_CR = "\\r?\\n";

  private static final ByteOrderMark[] SUPPORTED_BOMS = {
    ByteOrderMark.UTF_8, ByteOrderMark.UTF_16BE, ByteOrderMark.UTF_16LE
  };

  private static final Pattern SIGNATURE_BLOCK_PATTERN = Pattern.compile(
    "(?s)" + EOL + SIGNATURE_START + EOL + "(?<signature>.*)" + SIGNATURE_END + EOL
  );

  private static final Pattern SIGNATURE_BLOCK_REMOVAL_PATTERN = Pattern.compile(
    "(?s)" + EOL_OPTIONAL_CR + SIGNATURE_START + EOL_OPTIONAL_CR + ".*" + SIGNATURE_END + EOL_OPTIONAL_CR
  );

  public final String content;

  public PowerShellScript(InputStream input) throws IOException {
    this(input, StandardCharsets.UTF_8);
  }

  public PowerShellScript(InputStream input, Charset encoding) throws IOException {
    BOMInputStream stream = BOMInputStream.builder()
      .setInputStream(new BufferedInputStream(input))
      .setInclude(true)
      .setByteOrderMarks(SUPPORTED_BOMS)
      .get();

    try {
      String bomCharsetName = stream.getBOMCharsetName();
      if (bomCharsetName != null) {
        encoding = Charset.forName(bomCharsetName);
      }
      content = new String(stream.readAllBytes(), encoding);
    } finally {
      stream.close();
    }
  }

  public byte[] decodeSignatureBlock() {
    String block = getSignatureBlock();
    if (block == null) return null;
    String cleanedSignature = block.replace("# ", "").replace("\r", "").replace("\n", "");
    return Base64.getDecoder().decode(cleanedSignature);
  }

  private String getSignatureBlock() {
    Matcher matcher = SIGNATURE_BLOCK_PATTERN.matcher(content);
    if (!matcher.find()) return null;
    return matcher.group("signature");
  }

  public String getContentWithoutSignatureBlock() {
    return SIGNATURE_BLOCK_REMOVAL_PATTERN.matcher(content).replaceFirst("");
  }

  public byte[] computeDigest(MessageDigest digest) {
    digest.update(getContentWithoutSignatureBlock().getBytes(StandardCharsets.UTF_16LE));
    return digest.digest();
  }
}
