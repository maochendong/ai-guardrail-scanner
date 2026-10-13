package dev.aiguard.analysis;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.javaparsermodel.JavaParserFacade;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.MemoryTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import dev.aiguard.analysis.rules.ConfigurationRules;
import dev.aiguard.model.ScanModel.Diagnostic;
import dev.aiguard.model.ScanModel.ProjectMetadata;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

/** Static, bounded inventory. Target code and build scripts are never executed. */
public final class ProjectLoader {
    private static final Set<String> EXCLUDED = Set.of(".git", "target", "build", "node_modules", ".idea", ".gradle");
    private static final Pattern VERSION = Pattern.compile("(?:1\\.0|1\\.1|2\\.0)\\.\\d+(?:[-.][A-Za-z0-9]+)*");
    private static final Pattern PROPERTY = Pattern.compile("\\$\\{([^{}]+)}|\\$([A-Za-z_][A-Za-z0-9_]*)");
    private static final Pattern GRADLE_COORDINATE = Pattern.compile("(?:api|implementation|compileOnly|runtimeOnly|annotationProcessor|platform|enforcedPlatform|mavenBom)\\s*\\(?\\s*(['\"])(org\\.springframework\\.ai):([A-Za-z0-9_.-]+)(?::([^'\"\\r\\n]*))?\\1");
    private static final Pattern GRADLE_ASSIGNMENT = Pattern.compile("(?m)(?:^|[;{\\n])\\s*(?:(?:val|var|def)\\s+|ext\\.)?([A-Za-z_][A-Za-z0-9_.-]*)\\s*=\\s*(['\"])([^'\"\\r\\n]*)\\2");
    private final int maxFiles;
    private final long maxFileBytes;
    private final long maxTotalBytes;

    public ProjectLoader() { this(10_000, 2L * 1024 * 1024, 32L * 1024 * 1024); }

    public ProjectLoader(int maxFiles, long maxFileBytes, long maxTotalBytes) {
        if (maxFiles < 1 || maxFileBytes < 1 || maxTotalBytes < 1 || maxFileBytes > Integer.MAX_VALUE - 8L)
            throw new IllegalArgumentException("Budgets must be positive and individual files must fit in memory");
        this.maxFiles = maxFiles;
        this.maxFileBytes = maxFileBytes;
        this.maxTotalBytes = maxTotalBytes;
    }

    public SourceProject load(Path root, BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        if (!root.isAbsolute() || containsParent(root)) throw new IOException("Scan root must be an absolute path without parent traversal");
        Path absolute = root.normalize();
        for (Path p = absolute; p != null; p = p.getParent())
            if (Files.isSymbolicLink(p)) throw new IOException("Scan root must not contain symbolic links");
        Path real = absolute.toRealPath();
        if (!Files.isDirectory(real, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Scan root must be a directory");
        List<Diagnostic> diagnostics = new ArrayList<>();
        List<SourceProject.JavaSource> sources = new ArrayList<>();
        Map<String, String> configs = new LinkedHashMap<>();
        MessageDigest digest = sha256();
        MemoryTypeSolver memory = new MemoryTypeSolver();
        CombinedTypeSolver solver = new CombinedTypeSolver(memory, new ReflectionTypeSolver(true));
        JavaParser parser = new JavaParser(new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21)
                .setSymbolResolver(new JavaSymbolSolver(solver)));
        int javaFiles = 0;
        long totalBytes = 0;
        // Prefer anchored no-follow reads. Platforms without this API record the residual
        // race limitation and validate path components plus file identity before and after reading.
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(real)) {
            SecureDirectoryStream<Path> secure = stream instanceof SecureDirectoryStream<Path> anchored ? anchored : null;
            if (secure == null) diagnostics.add(new Diagnostic("FILESYSTEM_RACE_LIMITATION", "", "This filesystem lacks anchored directory reads; validated no-follow reads require a source tree that is not concurrently modified."));
            {
                List<Path> candidates = inventory(real, cancelled, diagnostics);
                for (Path path : candidates) {
                    checkCancelled(cancelled);
                    String relative = relative(real, path);
                    byte[] bytes;
                    long remaining = maxTotalBytes - totalBytes;
                    if (remaining == 0) {
                        diagnostics.add(new Diagnostic("TOTAL_BYTE_LIMIT", relative, "The total source byte budget was reached; remaining files were not read."));
                        break;
                    }
                    try {
                        bytes = secure == null ? readValidated(real, path, Math.min(maxFileBytes, remaining), cancelled)
                                : readAnchored(secure, real.relativize(path), Math.min(maxFileBytes, remaining), cancelled);
                    } catch (BudgetExceeded e) {
                        String code = remaining < maxFileBytes ? "TOTAL_BYTE_LIMIT" : "FILE_BYTE_LIMIT";
                        diagnostics.add(new Diagnostic(code, relative, "The source byte budget would be exceeded; this file was not parsed."));
                        if (remaining < maxFileBytes) break;
                        continue;
                    } catch (IOException | SecurityException e) {
                        diagnostics.add(new Diagnostic("READ_ERROR", relative, "The file could not be read safely; it was not parsed."));
                        continue;
                    }
                    totalBytes += bytes.length;
                    addDigest(digest, relative, bytes);
                    String content;
                    try { content = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString(); }
                    catch (CharacterCodingException e) {
                        diagnostics.add(new Diagnostic("ENCODING_ERROR", relative, "The file is not valid UTF-8; it was not parsed."));
                        continue;
                    }
                    if (relative.endsWith(".java")) {
                        javaFiles++;
                        try {
                            var parsed = parser.parse(content);
                            if (!parsed.isSuccessful() || parsed.getResult().isEmpty()) {
                                diagnostics.add(new Diagnostic("JAVA_PARSE_ERROR", relative, "Java parsing failed; partial syntax trees are excluded from assessment."));
                            } else {
                                sources.add(new SourceProject.JavaSource(relative, parsed.getResult().orElseThrow()));
                            }
                        } catch (RuntimeException | StackOverflowError e) {
                            diagnostics.add(new Diagnostic("JAVA_PARSE_ERROR", relative, "Java parsing failed; this file was excluded from assessment."));
                        }
                    } else configs.put(relative, content);
                }
            }
        }
        for (var source : sources) {
            checkCancelled(cancelled);
            for (TypeDeclaration<?> declaration : source.unit().findAll(TypeDeclaration.class)) {
                try {
                    var resolved = JavaParserFacade.get(solver).getTypeDeclaration(declaration);
                    String qualifiedName = resolved.getQualifiedName();
                    if (memory.tryToSolveType(qualifiedName).isSolved()) {
                        diagnostics.add(new Diagnostic("DUPLICATE_SOURCE_TYPE", source.path(), "Multiple included source types have the same qualified name; symbol resolution is ambiguous."));
                    } else memory.addDeclaration(qualifiedName, resolved);
                } catch (RuntimeException | StackOverflowError e) {
                    diagnostics.add(new Diagnostic("SYMBOL_INDEX_ERROR", source.path(), "A local source type could not be indexed; symbol resolution is incomplete."));
                }
            }
        }
        List<String> aiInputs = new ArrayList<>(sources.stream().filter(s -> referencesSpringAi(s.unit())).map(SourceProject.JavaSource::path).toList());
        for (var entry : configs.entrySet()) {
            checkCancelled(cancelled);
            if (ConfigurationRules.hasAiConfiguration(Map.of(entry.getKey(), entry.getValue()))) aiInputs.add(entry.getKey());
        }
        boolean inputAiDetected = !aiInputs.isEmpty();
        VersionProfile profile = versions(configs, aiInputs, diagnostics, cancelled);
        if ((inputAiDetected || profile.aiDetected) && !profile.supported())
            diagnostics.add(new Diagnostic("SPRING_AI_VERSION_UNKNOWN", "", "Spring AI version is unresolved, conflicting, or outside the supported explicit version families."));
        checkCancelled(cancelled);
        return new SourceProject(real, sources, configs,
                new ProjectMetadata(profile.version(), profile.supported() ? "SUPPORTED" : "UNKNOWN", javaFiles, configs.size(), inputAiDetected || profile.aiDetected),
                HexFormat.of().formatHex(digest.digest()), diagnostics);
    }

    private static boolean referencesSpringAi(CompilationUnit unit) {
        return unit.getImports().stream().anyMatch(i -> springAiName(i.getNameAsString()))
                || unit.findAll(ClassOrInterfaceType.class).stream().anyMatch(t -> springAiName(t.getNameWithScope()))
                || unit.findAll(AnnotationExpr.class).stream().anyMatch(a -> springAiName(a.getNameAsString()))
                || unit.findAll(FieldAccessExpr.class).stream().anyMatch(f -> springAiName(qualifiedName(f)));
    }

    /** Read identifier-only qualifier chains; strings, comments and arbitrary expression text are not evidence. */
    private static String qualifiedName(Expression expression) {
        if (expression instanceof NameExpr name) return name.getNameAsString();
        if (expression instanceof FieldAccessExpr field) {
            String scope = qualifiedName(field.getScope());
            return scope.isEmpty() ? "" : scope + "." + field.getNameAsString();
        }
        return "";
    }

    private static boolean springAiName(String name) {
        return name.equals("org.springframework.ai") || name.startsWith("org.springframework.ai.");
    }

    private List<Path> inventory(Path root, BooleanSupplier cancelled, List<Diagnostic> diagnostics) throws IOException {
        List<Path> paths = new ArrayList<>();
        long entryBudget = Math.max(1_000L, 20L * maxFiles);
        long[] entries = {0};
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            private boolean entry(Path path) {
                checkCancelled(cancelled);
                if (++entries[0] <= entryBudget) return true;
                diagnostics.add(new Diagnostic("ENTRY_LIMIT", relative(root, path), "Directory traversal budget was reached; inventory is incomplete."));
                return false;
            }
            @Override public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (!entry(dir)) return FileVisitResult.TERMINATE;
                Path rel = root.relativize(dir);
                if (!dir.equals(root) && (EXCLUDED.contains(dir.getFileName().toString()) || isTestPath(rel))) {
                    diagnostics.add(new Diagnostic("EXCLUDED_SCOPE", relative(root, dir), "Build output, tooling state, or test source is excluded from the default production-source scope."));
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (!entry(file)) return FileVisitResult.TERMINATE;
                if (attrs.isSymbolicLink()) diagnostics.add(new Diagnostic("SYMLINK_SKIPPED", relative(root, file), "A symbolic link was excluded; its target was not read."));
                else if (!attrs.isRegularFile()) diagnostics.add(new Diagnostic("NON_REGULAR_FILE", relative(root, file), "A non-regular file was excluded."));
                else if (selected(file)) {
                    if (paths.size() == maxFiles) {
                        diagnostics.add(new Diagnostic("FILE_LIMIT", relative(root, file), "The selected file count budget was reached; inventory is incomplete."));
                        return FileVisitResult.TERMINATE;
                    }
                    paths.add(file);
                }
                return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult visitFileFailed(Path file, IOException error) {
                if (!entry(file)) return FileVisitResult.TERMINATE;
                diagnostics.add(new Diagnostic("INVENTORY_ERROR", relative(root, file), "An entry could not be inspected; inventory is incomplete."));
                return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult postVisitDirectory(Path dir, IOException error) {
                if (error != null) diagnostics.add(new Diagnostic("INVENTORY_ERROR", relative(root, dir), "A directory could not be completely inspected."));
                return FileVisitResult.CONTINUE;
            }
        });
        paths.sort(Comparator.comparing(p -> relative(root, p)));
        return paths;
    }

    private static byte[] readAnchored(SecureDirectoryStream<Path> directory, Path relative, long limit, BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        if (relative.getNameCount() > 1) {
            try (SecureDirectoryStream<Path> child = directory.newDirectoryStream(relative.getName(0), LinkOption.NOFOLLOW_LINKS)) {
                return readAnchored(child, relative.subpath(1, relative.getNameCount()), limit, cancelled);
            }
        }
        var attributes = directory.getFileAttributeView(relative, java.nio.file.attribute.BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
        if (!attributes.isRegularFile()) throw new IOException("Not a regular file");
        try (SeekableByteChannel channel = directory.newByteChannel(relative, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
            return readChannel(channel, limit, cancelled);
        }
    }

    private static byte[] readValidated(Path root, Path file, long limit, BooleanSupplier cancelled) throws IOException {
        validateComponents(root, file);
        BasicFileAttributes before = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile()) throw new IOException("Not a regular file");
        byte[] bytes;
        try (SeekableByteChannel channel = Files.newByteChannel(file, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
            validateComponents(root, file);
            bytes = readChannel(channel, limit, cancelled);
        }
        validateComponents(root, file);
        BasicFileAttributes after = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!after.isRegularFile() || !Objects.equals(before.fileKey(), after.fileKey()) || before.size() != after.size()
                || !before.lastModifiedTime().equals(after.lastModifiedTime()) || after.size() != bytes.length)
            throw new IOException("File changed during reading");
        return bytes;
    }

    private static void validateComponents(Path root, Path file) throws IOException {
        if (!file.startsWith(root)) throw new IOException("Path escapes scan root");
        for (Path p = file; p != null; p = p.getParent())
            if (Files.isSymbolicLink(p)) throw new IOException("Symbolic path component");
        if (!file.toRealPath().equals(file) || !root.toRealPath().equals(root)) throw new IOException("Path changed during reading");
    }

    private static byte[] readChannel(SeekableByteChannel channel, long limit, BooleanSupplier cancelled) throws IOException {
        if (channel.size() > limit) throw new BudgetExceeded();
        ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.min(channel.size(), 8192));
        ByteBuffer buffer = ByteBuffer.allocate(8192);
        int count;
        while ((count = channel.read(buffer)) >= 0) {
            checkCancelled(cancelled);
            if (out.size() + (long) count > limit) throw new BudgetExceeded();
            out.write(buffer.array(), 0, count);
            buffer.clear();
        }
        return out.toByteArray();
    }

    private static VersionProfile versions(Map<String, String> configs, List<String> aiInputs,
                                           List<Diagnostic> diagnostics, BooleanSupplier cancelled) {
        VersionProfile profile = new VersionProfile();
        Map<String, VersionProfile> modules = new LinkedHashMap<>();
        Map<String, Pom> poms = new LinkedHashMap<>();
        for (var entry : configs.entrySet()) {
            checkCancelled(cancelled);
            if (Path.of(entry.getKey()).getFileName().toString().equals("pom.xml")) {
                try { poms.put(entry.getKey(), parsePom(entry.getValue())); }
                catch (Exception e) {
                    profile.unresolved = true;
                    diagnostics.add(new Diagnostic("XML_PARSE_ERROR", entry.getKey(), "Maven XML could not be safely parsed; DTDs and external entities are disabled."));
                }
            }
        }
        for (var entry : poms.entrySet()) {
            checkCancelled(cancelled);
            VersionProfile module = new VersionProfile();
            collectPom(entry.getKey(), poms, module);
            modules.put(entry.getKey(), module);
            profile.merge(module);
        }
        for (var entry : configs.entrySet()) {
            checkCancelled(cancelled);
            String name = Path.of(entry.getKey()).getFileName().toString();
            if (name.equals("build.gradle") || name.equals("build.gradle.kts")) {
                VersionProfile module = new VersionProfile();
                String source = stripComments(entry.getValue());
                Map<String, String> properties = new HashMap<>();
                String directory = entry.getKey().contains("/") ? entry.getKey().substring(0, entry.getKey().lastIndexOf('/') + 1) : "";
                // Only variables from this build's directory are used; unrelated modules cannot supply a version.
                String propertyFile = configs.get(directory + "gradle.properties");
                if (propertyFile != null) {
                    Properties values = new Properties();
                    try { values.load(new StringReader(propertyFile)); values.forEach((k, v) -> properties.put(k.toString(), v.toString())); }
                    catch (IOException | IllegalArgumentException e) { module.unresolved = true; }
                }
                Matcher assignment = GRADLE_ASSIGNMENT.matcher(source);
                while (assignment.find()) properties.put(assignment.group(1), assignment.group(3));
                Matcher extra = Pattern.compile("(?:extra|ext)\\s*\\[\\s*['\"]([^'\"]+)['\"]\\s*]\\s*=\\s*['\"]([^'\"]+)['\"]").matcher(source);
                while (extra.find()) properties.put(extra.group(1), extra.group(2));
                Matcher byExtra = Pattern.compile("(?:val|var)\\s+(\\w+)\\s+by\\s+extra\\(\\s*['\"]([^'\"]+)['\"]\\s*\\)").matcher(source);
                while (byExtra.find()) properties.put(byExtra.group(1), byExtra.group(2));
                Matcher allAssignments = Pattern.compile("(?m)(?:^|[;{\\n])\\s*(?:(?:val|var|def)\\s+|ext\\.)?([A-Za-z_][A-Za-z0-9_.-]*)\\s*=\\s*([^\\r\\n;}]*)").matcher(source);
                while (allAssignments.find()) {
                    if (!allAssignments.group(2).trim().matches("(['\"])[^'\"]*\\1")) properties.remove(allAssignments.group(1));
                }
                Matcher coordinate = GRADLE_COORDINATE.matcher(source);
                List<String> unmanaged = new ArrayList<>();
                boolean bom = false;
                boolean found = false;
                while (coordinate.find()) {
                    found = true;
                    module.aiDetected = true;
                    String version = coordinate.group(4);
                    if (coordinate.group(3).equals("spring-ai-bom") && version != null
                            && coordinate.group().matches("(?s)(?:platform|enforcedPlatform|mavenBom).*")) bom = true;
                    if (version == null || version.isBlank()) unmanaged.add(coordinate.group(3));
                    else module.add(resolve(version, properties));
                }
                if (!unmanaged.isEmpty() && !bom) module.unresolved = true;
                if (source.contains("org.springframework.ai") && !found) {
                    module.aiDetected = true;
                    module.unresolved = true;
                    diagnostics.add(new Diagnostic("GRADLE_VERSION_UNRESOLVED", entry.getKey(), "Spring AI dependency uses an unsupported Gradle declaration; scripts are not evaluated."));
                }
                modules.put(entry.getKey(), module);
                profile.merge(module);
            }
        }
        for (String input : aiInputs) {
            checkCancelled(cancelled);
            List<String> builds = nearestBuildFiles(input, configs);
            if (builds.isEmpty() || builds.stream().anyMatch(path -> !modules.containsKey(path) || !modules.get(path).supported())) {
                profile.unresolved = true;
                diagnostics.add(new Diagnostic("MODULE_VERSION_UNKNOWN", input, "This Spring AI source or configuration has no supported version established by its nearest module build declaration; sibling module versions are not inherited."));
            }
        }
        return profile;
    }

    private static List<String> nearestBuildFiles(String source, Map<String, String> configs) {
        Path directory = Path.of(source).getParent();
        while (true) {
            String prefix = directory == null ? "" : directory.toString().replace('\\', '/') + "/";
            List<String> builds = List.of(prefix + "pom.xml", prefix + "build.gradle", prefix + "build.gradle.kts")
                    .stream().filter(configs::containsKey).toList();
            if (!builds.isEmpty() || directory == null) return builds;
            directory = directory.getParent();
        }
    }

    private static void collectPom(String path, Map<String, Pom> poms, VersionProfile profile) {
        List<Pom> chain = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        String current = path;
        while (current != null && visited.add(current) && chain.size() < 32) {
            Pom pom = poms.get(current);
            if (pom == null) break;
            chain.add(0, pom);
            if (pom.parentPath == null) break;
            Path parent = Path.of(current).getParent();
            Path target = (parent == null ? Path.of(pom.parentPath) : parent.resolve(pom.parentPath)).normalize();
            current = target.toString().replace('\\', '/');
            if (current.startsWith("../") || target.isAbsolute()) break;
            Pom candidate = poms.get(current);
            if (candidate == null || !candidate.group.equals(pom.parentGroup) || !candidate.artifact.equals(pom.parentArtifact)
                    || !candidate.version.equals(resolve(pom.parentVersion, pom.properties))) break;
        }
        Map<String, String> properties = new HashMap<>();
        for (Pom pom : chain) properties.putAll(pom.properties);
        Map<String, String> managed = new HashMap<>();
        List<String> boms = new ArrayList<>();
        for (Pom pom : chain) for (Dependency dependency : pom.dependencies) {
            if (!resolve(dependency.group, properties).equals("org.springframework.ai")) continue;
            if (dependency.importBom) boms.add(resolve(dependency.version, properties));
            if (dependency.managed && !dependency.version.isBlank()) managed.put(dependency.artifact, resolve(dependency.version, properties));
        }
        Pom own = poms.get(path);
        for (Dependency dependency : own.dependencies) {
            if (!resolve(dependency.group, properties).equals("org.springframework.ai")) continue;
            profile.aiDetected = true;
            if (dependency.conditional) profile.unresolved = true;
            String version = resolve(dependency.version, properties);
            if (!version.isBlank()) profile.add(version);
            else if (managed.containsKey(dependency.artifact)) profile.add(managed.get(dependency.artifact));
            else if (!boms.isEmpty()) boms.forEach(profile::add);
            else profile.unresolved = true;
        }
    }

    private static Pom parsePom(String content) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        factory.setAttribute("http://www.oracle.com/xml/jaxp/properties/maxElementDepth", "128");
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        var builder = factory.newDocumentBuilder();
        builder.setErrorHandler(new DefaultHandler() {
            @Override public void error(SAXParseException e) throws SAXParseException { throw e; }
            @Override public void fatalError(SAXParseException e) throws SAXParseException { throw e; }
        });
        builder.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));
        Document document = builder.parse(new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
        Element project = document.getDocumentElement();
        if (!local(project).equals("project")) throw new IOException("Not a Maven project");
        Map<String, String> properties = new HashMap<>();
        Element props = child(project, "properties");
        if (props != null) for (Node n = props.getFirstChild(); n != null; n = n.getNextSibling())
            if (n instanceof Element e) properties.put(local(e), e.getTextContent().trim());
        Element parent = child(project, "parent");
        String parentGroup = parent == null ? "" : text(parent, "groupId");
        String parentArtifact = parent == null ? "" : text(parent, "artifactId");
        String parentVersion = parent == null ? "" : text(parent, "version");
        String projectGroup = text(project, "groupId").isBlank() ? parentGroup : text(project, "groupId");
        String projectVersion = text(project, "version").isBlank() ? parentVersion : text(project, "version");
        properties.put("project.version", projectVersion);
        properties.put("pom.version", projectVersion);
        properties.put("project.parent.version", parentVersion);
        String parentPath = parent == null ? null : child(parent, "relativePath") == null ? "../pom.xml" : text(parent, "relativePath");
        if (parentPath != null && parentPath.isBlank()) parentPath = null;
        List<Dependency> dependencies = new ArrayList<>();
        var nodes = project.getElementsByTagNameNS("*", "dependency");
        for (int i = 0; i < nodes.getLength(); i++) {
            Element dependency = (Element) nodes.item(i);
            boolean managed = false, conditional = false, plugin = false;
            for (Node n = dependency.getParentNode(); n instanceof Element; n = n.getParentNode()) {
                managed |= local(n).equals("dependencyManagement");
                conditional |= local(n).equals("profile");
                plugin |= local(n).equals("plugin");
            }
            if (!plugin) dependencies.add(new Dependency(text(dependency, "groupId"), text(dependency, "artifactId"), text(dependency, "version"), managed, conditional,
                    managed && text(dependency, "artifactId").equals("spring-ai-bom") && text(dependency, "type").equals("pom") && text(dependency, "scope").equals("import")));
        }
        return new Pom(properties, dependencies, parentPath, projectGroup, text(project, "artifactId"), resolve(projectVersion, properties), parentGroup, parentArtifact, parentVersion);
    }

    private static String resolve(String value, Map<String, String> properties) {
        final int expansionLimit = 4096;
        final String unresolved = "__UNRESOLVED__";
        if (value.length() > expansionLimit) return unresolved;
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 16 && seen.add(value); i++) {
            Matcher matcher = PROPERTY.matcher(value);
            StringBuffer out = new StringBuffer();
            boolean replaced = false;
            int lastEnd = 0;
            while (matcher.find()) {
                String key = matcher.group(1) == null ? matcher.group(2) : matcher.group(1);
                String replacement = properties.get(key);
                if (replacement != null) replaced = true;
                else replacement = matcher.group();
                if (replacement.length() > expansionLimit || out.length() + matcher.start() - lastEnd + replacement.length() > expansionLimit)
                    return unresolved;
                matcher.appendReplacement(out, Matcher.quoteReplacement(replacement));
                lastEnd = matcher.end();
            }
            if (out.length() + value.length() - lastEnd > expansionLimit) return unresolved;
            matcher.appendTail(out);
            if (!replaced) break;
            value = out.toString();
        }
        return value.trim();
    }

    private static String stripComments(String input) {
        StringBuilder result = new StringBuilder(input.length());
        char quote = 0;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (quote != 0) {
                result.append(c);
                if (c == '\\' && i + 1 < input.length()) result.append(input.charAt(++i));
                else if (c == quote) quote = 0;
            } else if (c == '\'' || c == '"') { quote = c; result.append(c); }
            else if (c == '/' && i + 1 < input.length() && input.charAt(i + 1) == '/') {
                while (i < input.length() && input.charAt(i) != '\n') { result.append(' '); i++; }
                if (i < input.length()) result.append('\n');
            } else if (c == '/' && i + 1 < input.length() && input.charAt(i + 1) == '*') {
                result.append("  "); i += 2;
                while (i < input.length() && !(input.charAt(i) == '*' && i + 1 < input.length() && input.charAt(i + 1) == '/')) {
                    result.append(input.charAt(i) == '\n' ? '\n' : ' '); i++;
                }
                if (i < input.length()) { result.append("  "); i++; }
            } else result.append(c);
        }
        return result.toString();
    }

    private static Element child(Element parent, String name) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling())
            if (n instanceof Element e && local(e).equals(name)) return e;
        return null;
    }
    private static String text(Element parent, String name) { Element c = child(parent, name); return c == null ? "" : c.getTextContent().trim(); }
    private static String local(Node node) { return node.getLocalName() == null ? node.getNodeName() : node.getLocalName(); }
    private static boolean selected(Path file) {
        String name = file.getFileName().toString();
        return name.endsWith(".java") || name.endsWith(".xml") || name.endsWith(".properties") || name.endsWith(".yml") || name.endsWith(".yaml")
                || name.equals("build.gradle") || name.equals("build.gradle.kts") || name.equals("settings.gradle") || name.equals("settings.gradle.kts");
    }
    private static boolean isTestPath(Path path) {
        for (int i = 0; i + 1 < path.getNameCount(); i++)
            if (path.getName(i).toString().equals("src") && Set.of("test", "testFixtures", "integrationTest").contains(path.getName(i + 1).toString())) return true;
        return false;
    }
    private static boolean containsParent(Path path) { for (Path part : path) if (part.toString().equals("..")) return true; return false; }
    private static String relative(Path root, Path file) { return root.relativize(file).toString().replace('\\', '/'); }
    private static void checkCancelled(BooleanSupplier cancelled) { if (cancelled.getAsBoolean() || Thread.currentThread().isInterrupted()) throw new CancellationException("Scan cancelled"); }
    private static MessageDigest sha256() { try { return MessageDigest.getInstance("SHA-256"); } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); } }
    private static void addDigest(MessageDigest digest, String path, byte[] bytes) {
        byte[] name = path.getBytes(StandardCharsets.UTF_8);
        digest.update(ByteBuffer.allocate(4).putInt(name.length).array()); digest.update(name);
        digest.update(ByteBuffer.allocate(8).putLong(bytes.length).array()); digest.update(bytes);
    }
    private static final class BudgetExceeded extends IOException {}
    private record Dependency(String group, String artifact, String version, boolean managed, boolean conditional, boolean importBom) {}
    private record Pom(Map<String, String> properties, List<Dependency> dependencies, String parentPath,
                       String group, String artifact, String version, String parentGroup, String parentArtifact, String parentVersion) {}
    private static final class VersionProfile {
        final Set<String> versions = new LinkedHashSet<>();
        boolean unresolved;
        boolean aiDetected;
        void merge(VersionProfile module) {
            versions.addAll(module.versions);
            unresolved |= module.unresolved;
            aiDetected |= module.aiDetected;
        }
        void add(String version) {
            // Only publish syntactic version literals, never an arbitrary build value or credential.
            if (version.length() <= 128 && version.matches("[0-9]+(?:\\.[0-9]+){1,3}(?:[-.][A-Za-z0-9]+)*")) versions.add(version);
            else unresolved = true;
        }
        boolean supported() { return !unresolved && versions.size() == 1 && VERSION.matcher(versions.iterator().next()).matches(); }
        String version() { return versions.isEmpty() ? "UNKNOWN" : versions.size() == 1 ? versions.iterator().next() : "CONFLICT"; }
    }
}
