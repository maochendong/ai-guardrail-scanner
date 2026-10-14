package dev.aiguard.compat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.*;

/** Bounded, source-only inventory. Never invokes target programs or opens databases. */
public final class Inventory {
  public final List<SourceFile> javaAndConfig = new ArrayList<SourceFile>();
  public final List<SourceFile> python = new ArrayList<SourceFile>();
  public final List<Map<String, Object>> diagnostics = new ArrayList<Map<String, Object>>();
  public int javaFiles, configurationFiles;
  public String digest;
  private long bytes;
  private int entries, selected;
  private static final Set<String> EXCLUDED =
      new HashSet<String>(
          Arrays.asList(
              ".git",
              "target",
              "build",
              "node_modules",
              ".idea",
              ".gradle",
              ".venv",
              "venv",
              "site-packages",
              "__pycache__",
              ".claude",
              ".agents",
              ".codex"));
  private static final long MAX_FILE = 2 * 1024 * 1024, MAX_TOTAL = 32 * 1024 * 1024;
  private final SortedMap<String, byte[]> read = new TreeMap<String, byte[]>();

  public static Inventory load(final Path root, final Cancel cancel) throws Exception {
    final Inventory result = new Inventory();
    PathPolicy.rejectLinks(root);
    // Java 7 NIO still cannot promise an atomic source-tree snapshot.
    result.diagnostic(
        "FILESYSTEM_RACE_LIMITATION",
        "",
        "Read-only path and file-identity checks do not provide an atomic source-tree snapshot;"
            + " keep the tree stable during scanning.");
    Files.walkFileTree(
        root,
        EnumSet.noneOf(FileVisitOption.class),
        128,
        new SimpleFileVisitor<Path>() {
          private boolean budget() {
            cancel.check();
            if (++result.entries > 200000) {
              result.diagnostic(
                  "INVENTORY_LIMIT",
                  "",
                  "Directory entry budget exhausted; remaining files were not assessed.");
              return false;
            }
            return true;
          }

          @Override
          public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
            if (!budget()) return FileVisitResult.TERMINATE;
            String relative = relative(root, dir);
            if (!dir.equals(root)
                && (EXCLUDED.contains(dir.getFileName().toString())
                    || testScope(relative)
                    || Files.isRegularFile(dir.resolve("pyvenv.cfg"), LinkOption.NOFOLLOW_LINKS))) {
              result.diagnostic(
                  "EXCLUDED_SCOPE",
                  relative,
                  "Build, dependency, tool or test directory excluded.");
              return FileVisitResult.SKIP_SUBTREE;
            }
            return FileVisitResult.CONTINUE;
          }

          @Override
          public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
            if (!budget()) return FileVisitResult.TERMINATE;
            String relative = relative(root, file);
            if (attrs.isSymbolicLink())
              result.diagnostic(
                  "SYMLINK_SKIPPED",
                  relative,
                  "Symbolic link skipped without following its target.");
            else if (attrs.isDirectory())
              result.diagnostic(
                  "DEPTH_LIMIT",
                  relative,
                  "Directory depth budget exhausted; descendants were not assessed.");
            else if (attrs.isRegularFile() && selected(file.getFileName().toString())) {
              if (++result.selected > 10000) {
                result.diagnostic(
                    "FILE_COUNT_LIMIT", relative, "Source/configuration file budget exhausted.");
                return FileVisitResult.TERMINATE;
              }
              result.read(root, file, relative, attrs, cancel);
            }
            return FileVisitResult.CONTINUE;
          }

          @Override
          public FileVisitResult visitFileFailed(Path file, IOException error) {
            cancel.check();
            result.diagnostic(
                "READ_ERROR", relative(root, file), "Directory entry could not be read safely.");
            return FileVisitResult.CONTINUE;
          }

          @Override
          public FileVisitResult postVisitDirectory(Path dir, IOException error) {
            cancel.check();
            if (error != null)
              result.diagnostic(
                  "READ_ERROR", relative(root, dir), "Directory could not be fully read.");
            return FileVisitResult.CONTINUE;
          }
        });
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    for (Map.Entry<String, byte[]> item : result.read.entrySet()) {
      cancel.check();
      digest.update(item.getKey().getBytes(StandardCharsets.UTF_8));
      digest.update((byte) 0);
      digest.update(item.getValue());
      digest.update((byte) 0);
    }
    StringBuilder hex = new StringBuilder();
    for (byte b : digest.digest()) hex.append(String.format(Locale.ROOT, "%02x", b & 255));
    result.digest = hex.toString();
    result.read.clear();
    Comparator<SourceFile> order =
        new Comparator<SourceFile>() {
          public int compare(SourceFile a, SourceFile b) {
            return a.path.compareTo(b.path);
          }
        };
    Collections.sort(result.javaAndConfig, order);
    Collections.sort(result.python, order);
    return result;
  }

  private void read(
      Path root, Path file, String relative, BasicFileAttributes before, Cancel cancel) {
    if (before.size() > MAX_FILE || before.size() > MAX_TOTAL - bytes) {
      diagnostic(
          "SOURCE_BYTE_LIMIT",
          relative,
          "File or cumulative source byte budget exceeded; file not read.");
      return;
    }
    try {
      PathPolicy.rejectLinks(file);
      if (!file.toRealPath().startsWith(root)) throw new IOException("PATH_ESCAPE");
      Set<OpenOption> options = new HashSet<OpenOption>();
      options.add(StandardOpenOption.READ);
      options.add(LinkOption.NOFOLLOW_LINKS);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      try (SeekableByteChannel channel = Files.newByteChannel(file, options)) {
        ByteBuffer buffer = ByteBuffer.allocate(8192);
        while (channel.read(buffer) >= 0) {
          cancel.check();
          buffer.flip();
          if (out.size() + buffer.remaining() > MAX_FILE
              || out.size() + buffer.remaining() > MAX_TOTAL - bytes)
            throw new IOException("BYTE_LIMIT");
          out.write(buffer.array(), 0, buffer.remaining());
          buffer.clear();
        }
      }
      PathPolicy.rejectLinks(file);
      BasicFileAttributes after =
          Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (!after.isRegularFile()
          || before.size() != after.size()
          || !before.lastModifiedTime().equals(after.lastModifiedTime())
          || !Objects.equals(before.fileKey(), after.fileKey())
          || !file.toRealPath().startsWith(root)) throw new IOException("SOURCE_CHANGED");
      byte[] content = out.toByteArray();
      bytes += content.length;
      read.put(relative, content);
      String decoded =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(content))
              .toString();
      SourceFile source = new SourceFile(relative, decoded);
      if (relative.endsWith(".py")) python.add(source);
      else {
        javaAndConfig.add(source);
        if (relative.endsWith(".java")) javaFiles++;
        else configurationFiles++;
      }
    } catch (CharacterCodingException error) {
      diagnostic("ENCODING_ERROR", relative, "File is not valid UTF-8; content not analyzed.");
    } catch (IOException error) {
      diagnostic("READ_ERROR", relative, "File could not be read safely; content not analyzed.");
    }
  }

  private static boolean selected(String name) {
    return name.endsWith(".java")
        || name.endsWith(".py")
        || name.equals("pom.xml")
        || name.equals("build.gradle")
        || name.equals("build.gradle.kts")
        || name.equals("gradle.properties")
        || name.startsWith("application")
            && (name.endsWith(".yml") || name.endsWith(".yaml") || name.endsWith(".properties"));
  }

  private static boolean testScope(String path) {
    return path.equals("src/test")
        || path.contains("/src/test/")
        || path.endsWith("/src/test")
        || path.endsWith("/src/testFixtures")
        || path.endsWith("/src/integrationTest")
        || path.equals("tests")
        || path.endsWith("/tests");
  }

  private static String relative(Path root, Path file) {
    return root.relativize(file).toString().replace('\\', '/');
  }

  private void diagnostic(String code, String path, String message) {
    if (diagnostics.size() < 2048) diagnostics.add(Findings.diagnostic(code, path, message));
    else if (diagnostics.size() == 2048)
      diagnostics.add(
          Findings.diagnostic(
              "DIAGNOSTIC_LIMIT", "", "Additional diagnostics omitted; coverage is incomplete."));
  }
}
