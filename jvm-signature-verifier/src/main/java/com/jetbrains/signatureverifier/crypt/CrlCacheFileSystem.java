package com.jetbrains.signatureverifier.crypt;

import org.bouncycastle.cert.X509CRLHolder;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class CrlCacheFileSystem {
  private final Path cacheDir;

  public CrlCacheFileSystem() {
    this("crlscache");
  }

  public CrlCacheFileSystem(String cacheDir) {
    this.cacheDir = Paths.get(System.getProperty("java.io.tmpdir"), cacheDir);
  }

  public Collection<X509CRLHolder> getCrls(String issuerId) throws Exception {
    List<Path> crlFiles = getCrlFiles(issuerId);
    List<X509CRLHolder> res = new ArrayList<>();
    for (Path path : crlFiles) {
      try (FileInputStream fis = new FileInputStream(path.toFile())) {
        res.add(new X509CRLHolder(fis));
      }
    }
    return res;
  }

  public void updateCrls(String issuerId, List<byte[]> crlsData) throws Exception {
    cleanUpCrls(issuerId);
    saveCrls(issuerId, crlsData);
  }

  private List<Path> getCrlFiles(String issuerId) throws IOException {
    ensureCacheDirectory();
    return Files.find(cacheDir, 1, (path, attrs) -> isMatchingCrl(path, issuerId))
      .collect(Collectors.toList());
  }

  private boolean isMatchingCrl(Path path, String issuerId) {
    String fileName = path.getFileName().toString();
    return fileName.startsWith(issuerId) && fileName.endsWith(".crl");
  }

  private void ensureCacheDirectory() throws IOException {
    if (!Files.exists(cacheDir))
      Files.createDirectory(cacheDir);
  }

  private void cleanUpCrls(String issuerId) throws Exception {
    for (Path crlFile : getCrlFiles(issuerId)) {
      Files.deleteIfExists(crlFile);
    }
  }

  private void saveCrls(String issuerId, List<byte[]> crlsData) throws IOException {
    if (crlsData.size() == 1) {
      saveCrl(issuerId + ".crl", crlsData.get(0));
    } else {
      for (int i = 0; i < crlsData.size(); i++) {
        saveCrl(issuerId + "_" + i + ".crl", crlsData.get(i));
      }
    }
  }

  private void saveCrl(String crlFileName, byte[] crlData) throws IOException {
    Path crlFilePath = cacheDir.resolve(crlFileName);
    Files.write(crlFilePath, crlData);
  }
}
