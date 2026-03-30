package com.jetbrains.signatureverifier;

import java.io.InputStream;

public final class Resources {
  public static InputStream GetDefaultRoots() {
    return getResourceStream("DefaultRoots.p7b");
  }

  private static InputStream getResourceStream(String name) {
    return Resources.class.getClassLoader().getResourceAsStream(name);
  }

  private Resources() {
  }
}
