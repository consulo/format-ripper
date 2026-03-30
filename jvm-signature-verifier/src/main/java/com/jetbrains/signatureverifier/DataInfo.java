package com.jetbrains.signatureverifier;

public final class DataInfo {
  private final int offset;
  private final int size;

  public DataInfo(int offset, int size) {
    this.offset = offset;
    this.size = size;
  }

  public int getOffset() {
    return offset;
  }

  public int getSize() {
    return size;
  }

  public boolean isEmpty() {
    return offset == 0 && size == 0;
  }

}
