package com.jetbrains.signatureverifier.cf;

public final class DirectoryEntryType {
  /** Unknown storage type */
  public static final byte STGTY_INVALID = 0;

  /** Element is a storage object */
  public static final byte STGTY_STORAGE = 1;

  /** Element is a stream object */
  public static final byte STGTY_STREAM = 2;

  /** Element is an ILockBytes object */
  public static final byte STGTY_LOCKBYTES = 3;

  /** Element is an IPropertyStorage object */
  public static final byte STGTY_PROPERTY = 4;

  /** Element is a root storage */
  public static final byte STGTY_ROOT = 5;

  private DirectoryEntryType() {
  }
}
