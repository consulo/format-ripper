package com.jetbrains.util.filetype;

import java.util.EnumSet;

/** Result of file type detection. {@code partial} is true when the format was identified by magic bytes but full parsing failed. */
public record DetectedFileInfo(FileType fileType, EnumSet<FileProperties> fileProperties, boolean partial) {
}
