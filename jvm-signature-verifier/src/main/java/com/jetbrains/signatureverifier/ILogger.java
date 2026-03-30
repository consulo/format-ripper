package com.jetbrains.signatureverifier;

public interface ILogger {
  void Info(String str);

  void Warning(String str);

  void Error(String str);

  void Trace(String str);
}
