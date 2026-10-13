package dev.aiguard.scan;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Authority is configured by the operator; tool arguments cannot extend it. */
public final class PathPolicy {
    private record Root(Path requested, Path real) {}
    private final List<Root> roots;
    private final Path output;

    public PathPolicy(List<Path> allowedRoots, Path output) throws IOException {
        if (allowedRoots.isEmpty()) throw new IllegalArgumentException("At least one allowed root is required.");
        var configured = new ArrayList<Root>();
        for (Path root : allowedRoots) {
            if (!root.isAbsolute()) throw new IllegalArgumentException("Allowed roots must be absolute.");
            Path real = root.toRealPath();
            if (!Files.isDirectory(real)) throw new IllegalArgumentException("Allowed root must be a directory.");
            configured.add(new Root(root.normalize(), real));
        }
        this.roots = List.copyOf(configured);
        if (!output.isAbsolute()) throw new IllegalArgumentException("Output must be absolute.");
        if (Files.isSymbolicLink(output)) throw new IllegalArgumentException("Output cannot be a symbolic link.");
        // Resolve the existing ancestor without creating anything inside a possible scan target.
        Path proposed = output.normalize();
        Path ancestor = proposed;
        while (!Files.exists(ancestor, LinkOption.NOFOLLOW_LINKS)) ancestor = ancestor.getParent();
        if (!Files.isDirectory(ancestor)) throw new IllegalArgumentException("Output ancestor must be a directory.");
        this.output = ancestor.toRealPath().resolve(ancestor.relativize(proposed));
    }

    public Path repository(Path requested) throws IOException {
        if (!requested.isAbsolute()) throw new IllegalArgumentException("Repository must be absolute.");
        Path lexical = requested.normalize();
        Root selected = roots.stream().filter(r -> lexical.startsWith(r.requested()) || lexical.startsWith(r.real()))
                .findFirst().orElseThrow(() -> new IllegalArgumentException("Repository is outside allowed roots."));
        Path prefix = lexical.startsWith(selected.requested()) ? selected.requested() : selected.real();
        Path walk = selected.real();
        for (Path segment : prefix.relativize(lexical)) {
            walk = walk.resolve(segment);
            if (Files.isSymbolicLink(walk)) throw new IllegalArgumentException("Repository path contains a symbolic link.");
        }
        Path real = lexical.toRealPath();
        if (!real.startsWith(selected.real()) || !Files.isDirectory(real, LinkOption.NOFOLLOW_LINKS))
            throw new IllegalArgumentException("Repository is outside allowed roots or not a directory.");
        if (real.startsWith(output) || output.startsWith(real))
            throw new IllegalArgumentException("Repository and output directory must not overlap.");
        return real;
    }

    public Path output() { return output; }
}
