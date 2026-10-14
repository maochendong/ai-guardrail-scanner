package dev.aiguard.compat;

public final class SourceFile {
  public final String path;
  public final String content;

  public SourceFile(String path, String content) {
    this.path = path;
    this.content = content;
  }
}
