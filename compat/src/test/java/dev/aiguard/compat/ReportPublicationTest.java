package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class ReportPublicationTest {
  @Rule public TemporaryFolder temporary = new TemporaryFolder();
  private static final Cancel NEVER = new Cancel() {
    public void check() {}
  };

  private Path folder(String name) throws IOException {
    return temporary.newFolder(name).toPath().toRealPath();
  }

  @Test
  public void cancellationDuringSerializationDoesNotPublishReports() throws Exception {
    assertStoppedDuringSerialization("cancel");
  }

  @Test
  public void closingDuringSerializationDoesNotPublishReports() throws Exception {
    assertStoppedDuringSerialization("close");
  }

  @Test
  public void timeoutDuringSerializationDoesNotPublishReports() throws Exception {
    assertStoppedDuringSerialization("timeout");
  }

  private void assertStoppedDuringSerialization(String operation) throws Exception {
    Path root = folder("repo"), output = folder("reports");
    final CountDownLatch entered = new CountDownLatch(1), resume = new CountDownLatch(1);
    ScanService service = new ScanService(Arrays.asList(root), output, new ScanService.Task() {
      public Map<String, Object> scan(Path path, String id, Cancel cancel) {
        return blockedReport(id, entered, resume);
      }
    }, "timeout".equals(operation) ? 1000 : 10000, 32);
    ExecutorService executor = executor(service);
    try {
      String id = (String) service.start(root).get("scanId");
      assertTrue("Serialization did not start", entered.await(5, TimeUnit.SECONDS));
      if ("close".equals(operation)) service.close();
      else if ("cancel".equals(operation))
        assertEquals("CANCELLED", service.cancel(id).get("state"));
      else Thread.sleep(1100);
      resume.countDown();
      if ("close".equals(operation))
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
      else drain(executor);
      Map<String, Object> status = service.status(id);
      assertEquals("timeout".equals(operation) ? "FAILED" : "CANCELLED", status.get("state"));
      if ("timeout".equals(operation)) assertEquals("SCAN_TIMEOUT", status.get("error"));
      assertFalse(Files.exists(output.resolve(id), LinkOption.NOFOLLOW_LINKS));
      assertEmpty(output);
    } finally {
      resume.countDown();
      service.close();
      assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
    }
  }

  private static Map<String, Object> blockedReport(
      String id, final CountDownLatch entered, final CountDownLatch resume) {
    Map<String, Object> report = new LinkedHashMap<String, Object>() {
      private boolean first = true;

      @Override
      public Set<Map.Entry<String, Object>> entrySet() {
        if (first) {
          first = false;
          entered.countDown();
          try {
            if (!resume.await(5, TimeUnit.SECONDS)) throw new AssertionError("Serialization blocked");
          } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
          }
        }
        return super.entrySet();
      }
    };
    report.putAll(InfrastructureTest.report(id));
    return report;
  }

  @Test
  public void cancellationAfterOneStagedFileCleansTemporaryFiles() throws Exception {
    final Path output = folder("staged");
    Path target = output.resolve("scan-id");
    try {
      Reports.prepare(InfrastructureTest.report("cancel"), target, new Cancel() {
        public void check() {
          try (DirectoryStream<Path> entries = Files.newDirectoryStream(output, ".guardrail-*")) {
            for (Path entry : entries)
              if (Files.exists(entry.resolve("report.json"))) throw new CancellationException();
          } catch (IOException error) {
            throw new AssertionError(error);
          }
        }
      });
      fail("Cancellation was not observed during staging");
    } catch (CancellationException expected) {
    }
    assertFalse(Files.exists(target));
    assertEmpty(output);
  }

  @Test
  public void cacheLimitDoesNotPublishAReport() throws Exception {
    Path root = folder("quota-repo"), output = folder("quota-out");
    ScanService service = new ScanService(Arrays.asList(root), output, new ScanService.Task() {
      public Map<String, Object> scan(Path path, String id, Cancel cancel) {
        return InfrastructureTest.report(id);
      }
    }, 10000, 32);
    Field cache = ScanService.class.getDeclaredField("cachedDocumentBytes");
    cache.setAccessible(true);
    cache.setLong(service, 64L * 1024 * 1024);
    try {
      String id = (String) service.start(root).get("scanId");
      drain(executor(service));
      assertEquals("FAILED", service.status(id).get("state"));
      assertEquals("SESSION_RESULT_LIMIT", service.status(id).get("error"));
      assertFalse(Files.exists(output.resolve(id)));
      assertEmpty(output);
    } finally {
      service.close();
    }
  }

  @Test
  public void stagedPublicationRejectsExistingFilesWithoutOverwriting() throws Exception {
    Path output = folder("existing"), target = Files.createDirectory(output.resolve("scan"));
    byte[] original = "operator-owned".getBytes(StandardCharsets.UTF_8);
    Files.write(target.resolve("report.json"), original);
    try (Reports.Prepared prepared = Reports.prepare(InfrastructureTest.report("existing"), target, NEVER)) {
      try {
        prepared.publish();
        fail("Existing report was accepted");
      } catch (IOException expected) {
        assertEquals("REPORT_DIRECTORY_NOT_EMPTY", expected.getMessage());
      }
    }
    assertArrayEquals(original, Files.readAllBytes(target.resolve("report.json")));
    assertEquals(1, entries(output));
  }

  @Test
  public void publicationRechecksDestinationSymlinksAfterPreparation() throws Exception {
    Path output = folder("links"), outside = folder("outside"), target = output.resolve("scan");
    try (Reports.Prepared prepared = Reports.prepare(InfrastructureTest.report("link"), target, NEVER)) {
      Files.createSymbolicLink(target, outside);
      try {
        prepared.publish();
        fail("Symlink destination was accepted");
      } catch (IOException expected) {
        assertEquals("SYMBOLIC_PATH", expected.getMessage());
      }
    }
    assertTrue(Files.isSymbolicLink(target));
    assertEmpty(outside);
    assertEquals(1, entries(output));
  }

  private static ExecutorService executor(ScanService service) throws Exception {
    Field field = ScanService.class.getDeclaredField("executor");
    field.setAccessible(true);
    return (ExecutorService) field.get(service);
  }

  private static void drain(ExecutorService executor) throws Exception {
    executor.submit(new Runnable() {
      public void run() {}
    }).get(5, TimeUnit.SECONDS);
  }

  private static int entries(Path directory) throws IOException {
    int count = 0;
    try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
      for (Path ignored : entries) count++;
    }
    return count;
  }

  private static void assertEmpty(Path directory) throws IOException {
    assertEquals("Unexpected report or staging file in " + directory, 0, entries(directory));
  }
}
