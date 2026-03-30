package com.jetbrains.signatureverifier.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;

class NullOutputStream extends OutputStream {
  @Override
  public void write(byte[] buf) throws IOException {
    // do nothing
  }

  @Override
  public void write(byte[] buf, int off, int len) throws IOException {
    // do nothing
  }

  @Override
  public void write(int b) throws IOException {
    // do nothing
  }
}
