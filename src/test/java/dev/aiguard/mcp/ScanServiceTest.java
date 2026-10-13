package dev.aiguard.mcp;

import dev.aiguard.model.ScanModel.*;
import dev.aiguard.scan.PathPolicy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

class ScanServiceTest {
    @TempDir Path temporary;
    Path repo() throws Exception { return Files.createDirectories(temporary.resolve("repos/app")).toRealPath(); }
    Path output() { return temporary.resolve("reports"); }
    Report report(String id) {
        return new Report("1.0", "test", id, "2026-10-13T00:00:00Z", "0".repeat(64),
                new ProjectMetadata("1.1.6", "SUPPORTED", 1, 1, true), false,
                List.of(new Assessment("TEST", Domain.L1, Disposition.UNKNOWN, Severity.INFO, "Unknown",
                        "External evidence is unavailable.", "Review external enforcement.", List.of(), List.of("Static only."))), List.of());
    }
    ScanService.Status waitFor(ScanService service, String id) throws Exception {
        long until = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < until) {
            var status = service.status(id);
            if (status.state() != ScanService.State.RUNNING) return status;
            Thread.sleep(10);
        }
        throw new AssertionError("Scan did not terminate");
    }

    @Test void rejectsEscapeSymlinksAndOutputOverlap() throws Exception {
        Path root = repo();
        var policy = new PathPolicy(List.of(root.getParent()), output());
        assertEquals(root, policy.repository(root));
        assertThrows(IllegalArgumentException.class, () -> policy.repository(root.resolve("../../reports")));
        Path link = root.getParent().resolve("alias"); Files.createSymbolicLink(link, root);
        assertThrows(IllegalArgumentException.class, () -> policy.repository(link));
        assertThrows(IllegalArgumentException.class, () -> policy.repository(Path.of("relative")));
        var overlapping = new PathPolicy(List.of(root), root.resolve("nested-output"));
        assertThrows(IllegalArgumentException.class, () -> overlapping.repository(root));
        assertFalse(Files.exists(root.resolve("nested-output")), "Rejected output must not mutate the source tree");
        var inverse = new PathPolicy(List.of(temporary.toRealPath()), temporary.toRealPath());
        assertThrows(IllegalArgumentException.class, () -> inverse.repository(root));
    }

    @Test void cancellationWinsBeforePublicationAndDoesNotFreeBusyWorkerEarly() throws Exception {
        Path root = repo(); var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
        try (var service = new ScanService(List.of(root), output(), (p, id, stop) -> {
            entered.countDown(); release.await(5, TimeUnit.SECONDS); return report(id);
        }, Duration.ofSeconds(10), 4)) {
            String id = service.start(root).scanId(); assertTrue(entered.await(3, TimeUnit.SECONDS));
            assertThrows(IllegalStateException.class, () -> service.start(root));
            assertEquals(ScanService.State.CANCELLED, service.cancel(id).state());
            assertThrows(IllegalStateException.class, () -> service.start(root));
            release.countDown();
            Thread.sleep(50);
            assertEquals(ScanService.State.CANCELLED, service.status(id).state());
            assertFalse(Files.exists(output().resolve(id)));
            assertThrows(IllegalStateException.class, () -> service.result(id, "json"));
        } finally { release.countDown(); }
    }

    @Test void completedResultsRemainImmutableAfterCancellationOrFileTampering() throws Exception {
        Path root = repo();
        try (var service = new ScanService(List.of(root), output(), (p, id, stop) -> report(id), Duration.ofSeconds(5), 1)) {
            String id = service.start(root).scanId();
            assertEquals(ScanService.State.COMPLETED, waitFor(service, id).state());
            assertFalse(service.status(id).coverageComplete()); assertEquals(1, service.status(id).unknowns());
            Object original = service.result(id, "json").get("content");
            Files.writeString(output().resolve(id).resolve("report.json"), "attacker instructions");
            assertEquals(original, service.result(id, "json").get("content"));
            assertEquals(ScanService.State.COMPLETED, service.cancel(id).state());
            assertThrows(IllegalStateException.class, () -> service.start(root));
            assertThrows(IllegalArgumentException.class, () -> service.result(id, "../../secret"));
            assertThrows(IllegalArgumentException.class, () -> service.status("missing"));
        }
    }

    @Test void exceptionAndTimeoutCannotYieldReports() throws Exception {
        Path root = repo();
        try (var service = new ScanService(List.of(root), output(), (p, id, stop) -> {
            throw new IllegalStateException("SECRET_FROM_SOURCE");
        }, Duration.ofSeconds(5), 2)) {
            String id = service.start(root).scanId(); var status = waitFor(service, id);
            assertEquals(ScanService.State.FAILED, status.state()); assertEquals("SCAN_FAILED", status.error());
            assertThrows(IllegalStateException.class, () -> service.result(id, "json"));
        }
        try (var service = new ScanService(List.of(root), output(), (p, id, stop) -> {
            Thread.sleep(50); return report(id);
        }, Duration.ofMillis(5), 2)) {
            String id = service.start(root).scanId();
            assertEquals("SCAN_TIMEOUT", waitFor(service, id).error());
            assertFalse(Files.exists(output().resolve(id)));
        }
    }

    @Test void closeCancelsRunningTaskAndRejectsNewWork() throws Exception {
        Path root = repo(); var entered = new CountDownLatch(1);
        var service = new ScanService(List.of(root), output(), (p, id, stop) -> {
            entered.countDown(); while (!stop.getAsBoolean()) Thread.sleep(5); return report(id);
        }, Duration.ofSeconds(5), 2);
        String id = service.start(root).scanId(); assertTrue(entered.await(2, TimeUnit.SECONDS));
        service.close();
        assertEquals(ScanService.State.CANCELLED, service.status(id).state());
        assertThrows(IllegalStateException.class, () -> service.start(root));
    }
}
