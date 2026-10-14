package dev.aiguard.compat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class PathPolicy {
  private final List<Path> requested = new ArrayList<Path>();
  private final List<Path> real = new ArrayList<Path>();
  private final Path output;

  public PathPolicy(List<Path> roots, Path output) throws IOException {
    if (roots.isEmpty() || !output.isAbsolute())
      throw new IllegalArgumentException("INVALID_SCOPE");
    for (Path root : roots) {
      if (!root.isAbsolute()) throw new IllegalArgumentException("INVALID_SCOPE");
      Path resolved = root.toRealPath();
      if (!Files.isDirectory(resolved)) throw new IllegalArgumentException("INVALID_SCOPE");
      requested.add(root.normalize());
      real.add(resolved);
    }
    Path proposed = output.normalize();
    rejectLinks(proposed);
    Path ancestor = proposed;
    while (!Files.exists(ancestor, LinkOption.NOFOLLOW_LINKS)) ancestor = ancestor.getParent();
    if (!Files.isDirectory(ancestor)) throw new IllegalArgumentException("INVALID_OUTPUT");
    this.output = ancestor.toRealPath().resolve(ancestor.relativize(proposed));
  }

  public Path repository(Path path) throws IOException {
    if (!path.isAbsolute()) throw new IllegalArgumentException("INVALID_SCOPE");
    Path lexical = path.normalize();
    for (int i = 0; i < real.size(); i++) {
      Path prefix = lexical.startsWith(requested.get(i)) ? requested.get(i) : real.get(i);
      if (!lexical.startsWith(prefix)) continue;
      Path current = real.get(i);
      for (Path part : prefix.relativize(lexical)) {
        current = current.resolve(part);
        if (Files.isSymbolicLink(current)) throw new IllegalArgumentException("INVALID_SCOPE");
      }
      Path resolved = lexical.toRealPath();
      if (!resolved.startsWith(real.get(i))
          || !Files.isDirectory(resolved, LinkOption.NOFOLLOW_LINKS))
        throw new IllegalArgumentException("INVALID_SCOPE");
      if (resolved.startsWith(output) || output.startsWith(resolved))
        throw new IllegalArgumentException("INVALID_SCOPE");
      return resolved;
    }
    throw new IllegalArgumentException("INVALID_SCOPE");
  }

  static void rejectLinks(Path path) throws IOException {
    Path current = path.toAbsolutePath().getRoot();
    for (Path segment : path.toAbsolutePath()) {
      current = current.resolve(segment);
      if (Files.isSymbolicLink(current)) throw new IOException("SYMBOLIC_PATH");
    }
  }

  public Path output() {
    return output;
  }
}
