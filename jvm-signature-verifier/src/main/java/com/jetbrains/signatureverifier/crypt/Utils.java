package com.jetbrains.signatureverifier.crypt;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;

public class Utils {
  public static String flatMessages(Throwable throwable) {
    StringBuilder sb = new StringBuilder(throwable.getMessage());
    while (throwable.getCause() != null) {
      throwable = throwable.getCause();
      sb.append(System.lineSeparator()).append(throwable.getMessage());
    }
    return sb.toString();
  }

  public static LocalDateTime convertToLocalDateTime(Date date) {
    return LocalDateTime.ofInstant(date.toInstant(), ZoneId.systemDefault());
  }

  public static Date convertToDate(LocalDateTime localDateTime) {
    return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
  }

  public static String toString(LocalDateTime localDateTime, String format) {
    if (localDateTime == null) return null;
    return DateTimeFormatter.ofPattern(format).format(localDateTime);
  }
}
