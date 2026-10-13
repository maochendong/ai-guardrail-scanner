package dev.aiguard.analysis;

import static org.junit.jupiter.api.Assertions.*;

import com.github.javaparser.ast.expr.MethodCallExpr;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;

class ProjectLoaderTest {
    @TempDir Path root;

    @BeforeEach void canonicalRoot() throws IOException { root = root.toRealPath(); }

    @Test void detectsMavenPropertyBomAndAiImportWithoutTargetBuild() throws Exception {
        write("pom.xml", pom("<properties><spring-ai.version>1.1.4</spring-ai.version></properties>"
                + management(dependency("spring-ai-bom", "${spring-ai.version}"))
                + "<dependencies>" + dependency("spring-ai-starter-model-openai", "") + "</dependencies>"));
        write("src/main/java/Demo.java", "import org.springframework.ai.chat.client.ChatClient; class Demo { ChatClient client; }");
        write("gradlew", "#!/bin/sh\ntouch SHOULD_NEVER_EXIST");
        var project = load();
        assertTrue(project.metadata().aiDetected());
        assertTrue(project.supportedVersion());
        assertEquals("1.1.4", project.metadata().springAiVersion());
        assertEquals(1, project.metadata().javaFiles());
        assertEquals(1, project.metadata().configurationFiles());
        assertFalse(Files.exists(root.resolve("SHOULD_NEVER_EXIST")));
        assertTrue(project.diagnostics().stream().allMatch(d -> d.code().equals("FILESYSTEM_RACE_LIMITATION")), project.diagnostics().toString());
    }

    @Test void malformedJavaIsExcludedWithoutEchoingSource() throws Exception {
        write("Broken.java", "class Broken { String secret = \"TOP_SECRET_123\"; void x( { }");
        var project = load();
        assertEquals(1, project.metadata().javaFiles());
        assertTrue(project.sources().isEmpty());
        assertDiagnostic(project, "JAVA_PARSE_ERROR");
        assertFalse(project.diagnostics().toString().contains("TOP_SECRET_123"));
    }

    @Test void blocksExternalXmlEntitiesWithoutReadingOrEchoingThem() throws Exception {
        Path external = Files.createTempFile("aiguard-secret-", ".txt");
        try {
            Files.writeString(external, "PRIVATE_CREDENTIAL_456");
            write("pom.xml", "<!DOCTYPE project [<!ENTITY secret SYSTEM '" + external.toUri() + "'>]>"
                    + "<project><properties><version>&secret;</version></properties></project>");
            var project = load();
            assertDiagnostic(project, "XML_PARSE_ERROR");
            assertFalse(project.supportedVersion());
            assertFalse(project.diagnostics().toString().contains("PRIVATE_CREDENTIAL_456"));
            assertFalse(project.diagnostics().toString().contains(external.toString()));
        } finally { Files.deleteIfExists(external); }
    }

    @Test void unresolvedVersionPropertyNeverBecomesSupported() throws Exception {
        write("pom.xml", pom(management(dependency("spring-ai-bom", "${external.version}"))));
        var project = load();
        assertFalse(project.supportedVersion());
        assertTrue(project.metadata().aiDetected());
        assertEquals("UNKNOWN", project.metadata().springAiVersion());
        assertDiagnostic(project, "SPRING_AI_VERSION_UNKNOWN");
    }

    @Test void conflictsAcrossModulesAreUnknown() throws Exception {
        write("a/pom.xml", pom("<dependencies>" + dependency("spring-ai-core", "1.0.0") + "</dependencies>"));
        write("b/pom.xml", pom("<dependencies>" + dependency("spring-ai-model", "1.1.0") + "</dependencies>"));
        var project = load();
        assertFalse(project.supportedVersion());
        assertEquals("CONFLICT", project.metadata().springAiVersion());
    }

    @Test void bomFromUnrelatedModuleCannotSupplyMissingVersion() throws Exception {
        write("a/pom.xml", pom(management(dependency("spring-ai-bom", "1.1.0"))));
        write("b/pom.xml", pom("<dependencies>" + dependency("spring-ai-model", "") + "</dependencies>"));
        assertFalse(load().supportedVersion());
    }

    @Test void resolvesIncludedLocalParentPropertiesAndBom() throws Exception {
        write("pom.xml", pom("<groupId>sample</groupId><artifactId>parent</artifactId><version>1</version>"
                + "<properties><springAiVersion>2.0.0-M1</springAiVersion></properties>"
                + management(dependency("spring-ai-bom", "${springAiVersion}"))));
        write("child/pom.xml", pom("<parent><groupId>sample</groupId><artifactId>parent</artifactId><version>1</version></parent>"
                + "<dependencies>" + dependency("spring-ai-model", "") + "</dependencies>"));
        write("child/src/main/java/Child.java", "class Child { org.springframework.ai.chat.client.ChatClient client; }");
        assertTrue(load().supportedVersion());
        assertEquals("2.0.0-M1", load().metadata().springAiVersion());
    }

    @Test void excludesTestsBuildAndToolDirectoriesWithScopeEvidence() throws Exception {
        for (String dir : new String[]{".git", "target", "build", "node_modules", ".idea", "src/test/java", "module/src/integrationTest/java"})
            write(dir + "/Ignored.java", "not valid java SECRET");
        write("src/main/java/Production.java", "class Production {}");
        var project = load();
        assertEquals(1, project.sources().size());
        assertEquals(7, project.diagnostics().stream().filter(d -> d.code().equals("EXCLUDED_SCOPE")).count());
        assertTrue(project.diagnostics().stream().noneMatch(d -> d.code().equals("JAVA_PARSE_ERROR")));
    }

    @Test void skipsFileAndDirectorySymlinksEvenWhenTargetIsInsideRoot() throws Exception {
        Path outside = Files.createTempDirectory("aiguard-outside-");
        try {
            Files.writeString(outside.resolve("Outside.java"), "class Outside {}");
            Files.createSymbolicLink(root.resolve("linked"), outside);
            Files.createSymbolicLink(root.resolve("Alias.java"), outside.resolve("Outside.java"));
            write("Inside.java", "class Inside {}");
            Files.createSymbolicLink(root.resolve("InsideAlias.java"), root.resolve("Inside.java"));
            var project = load();
            assertEquals(1, project.sources().size());
            assertEquals(3, project.diagnostics().stream().filter(d -> d.code().equals("SYMLINK_SKIPPED")).count());
            assertTrue(project.diagnostics().stream().noneMatch(d -> d.path().contains("Outside.java")));
        } finally { Files.deleteIfExists(outside.resolve("Outside.java")); Files.deleteIfExists(outside); }
    }

    @Test void rejectsRootTraversalAndRootSymlink() throws Exception {
        write("Inner.java", "class Inner {}");
        assertThrows(IOException.class, () -> new ProjectLoader().load(root.resolve("child/.."), () -> false));
        assertThrows(IOException.class, () -> new ProjectLoader().load(Path.of("."), () -> false));
        Path alias = root.resolve("root-alias");
        Files.createSymbolicLink(alias, root);
        assertThrows(IOException.class, () -> new ProjectLoader().load(alias, () -> false));
    }

    @Test void fileCountBudgetIsReported() throws Exception {
        write("A.java", "class A {}"); write("B.java", "class B {}");
        var project = new ProjectLoader(1, 1024, 2048).load(root, () -> false);
        assertEquals(1, project.sources().size());
        assertDiagnostic(project, "FILE_LIMIT");
    }

    @Test void fileByteBudgetSkipsOversizeWithoutParsing() throws Exception {
        write("Huge.java", "class Huge { } //" + "x".repeat(100));
        var project = new ProjectLoader(10, 32, 256).load(root, () -> false);
        assertTrue(project.sources().isEmpty());
        assertDiagnostic(project, "FILE_BYTE_LIMIT");
    }

    @Test void totalByteBudgetStopsRemainingFiles() throws Exception {
        write("A.java", "class A {} //" + "x".repeat(30));
        write("B.java", "class B {} //" + "x".repeat(30));
        var project = new ProjectLoader(10, 100, 60).load(root, () -> false);
        assertEquals(1, project.sources().size());
        assertDiagnostic(project, "TOTAL_BYTE_LIMIT");
    }

    @Test void cancellationInterruptsInventoryAndDoesNotReturnPartialSuccess() throws Exception {
        assertThrows(CancellationException.class, () -> new ProjectLoader().load(root, () -> true));
        for (int i = 0; i < 10; i++) write("Type" + i + ".java", "class Type" + i + " {}");
        AtomicInteger calls = new AtomicInteger();
        assertThrows(CancellationException.class, () -> new ProjectLoader().load(root, () -> calls.incrementAndGet() > 5));
    }

    @Test void digestIsDeterministicAndSensitiveToContentsAndRelativePaths() throws Exception {
        write("A.java", "class A {}");
        String original = load().digest();
        assertEquals(64, original.length());
        assertEquals(original, load().digest());
        write("A.java", "class A { int value; }");
        assertNotEquals(original, load().digest());
        write("A.java", "class A {}");
        Files.move(root.resolve("A.java"), root.resolve("Renamed.java"));
        assertNotEquals(original, load().digest());
    }

    @Test void resolvesLocalSourceSymbolsWithoutExternalDependencies() throws Exception {
        write("src/main/java/demo/A.java", "package demo; class A { String value() { return \"ok\"; } }");
        write("src/main/java/demo/B.java", "package demo; class B { String call() { return new A().value(); } }");
        var project = load();
        MethodCallExpr call = project.sources().stream().filter(s -> s.path().endsWith("B.java")).findFirst().orElseThrow()
                .unit().findFirst(MethodCallExpr.class).orElseThrow();
        assertEquals("demo.A.value", call.resolve().getQualifiedName());
    }

    @Test void gradleLiteralAndCommonVersionVariablesAreRecognized() throws Exception {
        write("build.gradle.kts", "val springAiVersion = \"1.1.3\"\ndependencies {\n"
                + "implementation(platform(\"org.springframework.ai:spring-ai-bom:$springAiVersion\"))\n"
                + "implementation(\"org.springframework.ai:spring-ai-starter-model-openai\")\n}\n");
        assertTrue(load().supportedVersion());
        assertEquals("1.1.3", load().metadata().springAiVersion());
    }

    @Test void gradlePropertiesResolveAndCommentsDoNotCreateConflicts() throws Exception {
        write("gradle.properties", "springAiVersion=1.0.2\n");
        write("build.gradle", "// implementation 'org.springframework.ai:spring-ai-model:0.8.0'\n"
                + "dependencies { implementation 'org.springframework.ai:spring-ai-model:${springAiVersion}' }\n"
                + "/* implementation 'org.springframework.ai:spring-ai-model:9.0.0' */");
        assertTrue(load().supportedVersion());
        assertEquals("1.0.2", load().metadata().springAiVersion());
    }

    @Test void dynamicGradleVersionRemainsUnknownAndDoesNotLeakLiteral() throws Exception {
        write("build.gradle", "dependencies { implementation 'org.springframework.ai:spring-ai-model:PRIVATE_SECRET_VALUE' }");
        var project = load();
        assertFalse(project.supportedVersion());
        assertFalse(project.metadata().toString().contains("PRIVATE_SECRET_VALUE"));
        assertFalse(project.diagnostics().toString().contains("PRIVATE_SECRET_VALUE"));
    }

    @Test void unsupportedVersionFamilyAndImportWithoutDependencyAreUnknown() throws Exception {
        write("pom.xml", pom("<dependencies>" + dependency("spring-ai-core", "0.8.1") + "</dependencies>"));
        assertFalse(load().supportedVersion());
        Files.delete(root.resolve("pom.xml"));
        write("App.java", "import org.springframework.ai.chat.client.ChatClient; class App {}");
        assertTrue(load().metadata().aiDetected());
        assertFalse(load().supportedVersion());
    }

    @Test void malformedEncodingIsNotSilentlyReplaced() throws Exception {
        Files.write(root.resolve("Bad.java"), new byte[]{(byte) 0xc3, (byte) 0x28});
        assertDiagnostic(load(), "ENCODING_ERROR");
    }

    @Test void regularBomDependencyDoesNotManageOtherDependencies() throws Exception {
        write("pom.xml", pom("<dependencies>" + dependency("spring-ai-bom", "1.1.0")
                + dependency("spring-ai-model", "") + "</dependencies>"));
        assertFalse(load().supportedVersion());
        Files.delete(root.resolve("pom.xml"));
        write("build.gradle", "dependencies { implementation 'org.springframework.ai:spring-ai-bom:1.1.0'\n"
                + "implementation 'org.springframework.ai:spring-ai-model' }");
        assertFalse(load().supportedVersion());
    }

    @Test void arbitraryGradleStringIsNotAResolvedDependency() throws Exception {
        write("build.gradle", "def example = 'org.springframework.ai:spring-ai-model:1.1.0'\n");
        assertFalse(load().supportedVersion());
    }

    @Test void dynamicReassignmentInvalidatesPreviouslyKnownGradleVariable() throws Exception {
        write("build.gradle", "def springAiVersion = '1.1.0'\nspringAiVersion = computeVersion()\n"
                + "dependencies { implementation \"org.springframework.ai:spring-ai-model:$springAiVersion\" }");
        assertFalse(load().supportedVersion());
    }

    @Test void parentWithDifferentCoordinatesCannotSupplyVersion() throws Exception {
        write("pom.xml", pom("<groupId>other</groupId><artifactId>parent</artifactId><version>1</version>"
                + management(dependency("spring-ai-bom", "1.1.0"))));
        write("child/pom.xml", pom("<parent><groupId>sample</groupId><artifactId>parent</artifactId><version>1</version></parent>"
                + "<dependencies>" + dependency("spring-ai-model", "") + "</dependencies>"));
        assertFalse(load().supportedVersion());
    }

    @Test void deeplyNestedXmlIsBoundedAndReported() throws Exception {
        write("pom.xml", "<project>" + "<deep>".repeat(200) + "value" + "</deep>".repeat(200) + "</project>");
        assertDiagnostic(load(), "XML_PARSE_ERROR");
    }

    @Test void fullyQualifiedAiTypeWithoutImportOrDependencyIsDetectedWithUnknownVersion() throws Exception {
        write("App.java", "class App { org.springframework.ai.chat.client.ChatClient client; "
                + "String call(String q) { return client.prompt().user(q).call().content(); } }");
        assertUnknownAi(load());
    }

    @Test void fullyQualifiedAiAnnotationWithoutImportIsDetected() throws Exception {
        write("App.java", "class App { @org.springframework.ai.tool.annotation.Tool String work() { return \"ok\"; } }");
        assertUnknownAi(load());
    }

    @Test void fullyQualifiedAiStaticFactoryWithoutImportIsDetected() throws Exception {
        write("App.java", "class App { Object work(Object model) { return org.springframework.ai.chat.client.ChatClient.builder(model); } }");
        assertUnknownAi(load());
    }

    @Test void stringsCommentsAndSimilarPackagesDoNotCreateAiDetection() throws Exception {
        write("App.java", "/* org.springframework.ai.chat.client.ChatClient */ class App { "
                + "String reference = \"org.springframework.ai.chat.client.ChatClient.builder(model)\"; "
                + "org.springframework.aiExtra.ChatClient unrelated; }");
        assertFalse(load().metadata().aiDetected());
    }

    @Test void rootAiPackageWildcardImportIsDetected() throws Exception {
        write("App.java", "import org.springframework.ai.*; class App {}");
        assertUnknownAi(load());
    }

    @Test void siblingMavenModuleVersionCannotAuthorizeSourceWithoutDependencyDeclaration() throws Exception {
        write("a/pom.xml", pom("<dependencies>" + dependency("spring-ai-model", "1.1.0") + "</dependencies>"));
        write("b/pom.xml", pom("<artifactId>module-b</artifactId>"));
        write("b/src/main/java/App.java", "class App { org.springframework.ai.chat.client.ChatClient client; }");
        var project = load();
        assertTrue(project.metadata().aiDetected());
        assertFalse(project.supportedVersion());
        assertDiagnostic(project, "MODULE_VERSION_UNKNOWN");
    }

    @Test void nearestBuildFilePreventsUsingAncestorVersionWithoutInheritance() throws Exception {
        write("pom.xml", pom(management(dependency("spring-ai-bom", "1.1.0"))));
        write("b/pom.xml", pom("<artifactId>module-b</artifactId>"));
        write("b/src/main/java/App.java", "class App { org.springframework.ai.chat.client.ChatClient client; }");
        assertFalse(load().supportedVersion());
        assertDiagnostic(load(), "MODULE_VERSION_UNKNOWN");
    }

    @Test void sourceWithoutAnyOwningBuildCannotBorrowSiblingVersion() throws Exception {
        write("a/pom.xml", pom("<dependencies>" + dependency("spring-ai-model", "1.1.0") + "</dependencies>"));
        write("b/src/main/java/App.java", "class App { org.springframework.ai.chat.client.ChatClient client; }");
        assertFalse(load().supportedVersion());
        assertDiagnostic(load(), "MODULE_VERSION_UNKNOWN");
    }

    @Test void siblingGradleModuleVersionCannotAuthorizeSourceWithoutDependencyDeclaration() throws Exception {
        write("a/build.gradle", "dependencies { implementation 'org.springframework.ai:spring-ai-model:1.1.0' }");
        write("b/build.gradle.kts", "plugins { java }");
        write("b/src/main/java/App.java", "class App { org.springframework.ai.chat.client.ChatClient client; }");
        assertFalse(load().supportedVersion());
        assertDiagnostic(load(), "MODULE_VERSION_UNKNOWN");
    }

    @Test void singleGradleModuleWithExplicitVersionAndAiSourceRemainsSupported() throws Exception {
        write("build.gradle", "dependencies { implementation 'org.springframework.ai:spring-ai-model:1.1.0' }");
        write("src/main/java/App.java", "class App { org.springframework.ai.chat.client.ChatClient client; }");
        assertTrue(load().supportedVersion());
    }

    @Test void recursiveExpandingMavenPropertiesAreBounded() throws Exception {
        write("pom.xml", pom("<properties><expanding>" + "${expanding}".repeat(64) + "</expanding></properties>"
                + "<dependencies>" + dependency("spring-ai-model", "${expanding}") + "</dependencies>"));
        var project = assertTimeout(java.time.Duration.ofSeconds(3), this::load);
        assertUnknownAi(project);
        assertFalse(project.diagnostics().toString().contains("${expanding}"));
    }

    @Test void recursiveGradlePropertiesAreBounded() throws Exception {
        write("gradle.properties", "expanding=" + "${expanding}".repeat(64) + "\n");
        write("build.gradle", "dependencies { implementation 'org.springframework.ai:spring-ai-model:${expanding}' }");
        assertUnknownAi(assertTimeout(java.time.Duration.ofSeconds(3), this::load));
    }

    @Test void circularPropertiesRemainUnknown() throws Exception {
        write("pom.xml", pom("<properties><a>${b}</a><b>${a}</b></properties>"
                + "<dependencies>" + dependency("spring-ai-model", "${a}") + "</dependencies>"));
        assertUnknownAi(assertTimeout(java.time.Duration.ofSeconds(3), this::load));
    }

    @Test void oversizedPropertyAndVersionLiteralAreNotExported() throws Exception {
        String longVersion = "1.1.0-" + "x".repeat(5000);
        write("pom.xml", pom("<properties><oversized>" + longVersion + "</oversized></properties>"
                + "<dependencies>" + dependency("spring-ai-model", "${oversized}") + "</dependencies>"));
        assertUnknownAi(load());
        write("pom.xml", pom("<dependencies>" + dependency("spring-ai-model", "1.1.0-" + "x".repeat(150)) + "</dependencies>"));
        var project = load();
        assertUnknownAi(project);
        assertTrue(project.metadata().springAiVersion().length() < 128);
    }

    @Test void pureAiPropertiesWithoutDependenciesAreDetectedWithUnknownVersion() throws Exception {
        write("src/main/resources/application.properties", "spring.ai.chat.client.observations.log-prompt=true\n");
        assertUnknownAi(load());
        assertDiagnostic(load(), "MODULE_VERSION_UNKNOWN");
    }

    @Test void disabledAiYamlFlagStillIdentifiesAiConfiguration() throws Exception {
        write("src/main/resources/application.yml", "spring:\n  ai:\n    tools:\n      observations:\n        include-content: false\n");
        assertUnknownAi(load());
    }

    @Test void aiConfigurationCommentsDoNotIdentifyAiApplication() throws Exception {
        write("application.properties", "# spring.ai.chat.client.observations.log-prompt=true\nother.enabled=true\n");
        assertFalse(load().metadata().aiDetected());
    }

    @Test void aiConfigurationCannotBorrowSiblingModuleVersion() throws Exception {
        write("a/pom.xml", pom("<dependencies>" + dependency("spring-ai-model", "1.1.0") + "</dependencies>"));
        write("b/pom.xml", pom("<artifactId>module-b</artifactId>"));
        write("b/src/main/resources/application.properties", "spring.ai.tools.observations.include-content=true\n");
        assertFalse(load().supportedVersion());
        assertDiagnostic(load(), "MODULE_VERSION_UNKNOWN");
    }

    private static void assertUnknownAi(SourceProject project) {
        assertTrue(project.metadata().aiDetected());
        assertFalse(project.supportedVersion());
        assertEquals("UNKNOWN", project.metadata().springAiVersion());
        assertDiagnostic(project, "SPRING_AI_VERSION_UNKNOWN");
    }

    private SourceProject load() throws IOException { return new ProjectLoader().load(root, () -> false); }
    private void write(String name, String content) throws IOException {
        Path path = root.resolve(name); Files.createDirectories(path.getParent()); Files.writeString(path, content, StandardCharsets.UTF_8);
    }
    private static void assertDiagnostic(SourceProject project, String code) {
        assertTrue(project.diagnostics().stream().anyMatch(d -> d.code().equals(code)), project.diagnostics().toString());
    }
    private static String pom(String body) { return "<project xmlns='http://maven.apache.org/POM/4.0.0'><modelVersion>4.0.0</modelVersion>" + body + "</project>"; }
    private static String dependency(String artifact, String version) {
        return "<dependency><groupId>org.springframework.ai</groupId><artifactId>" + artifact + "</artifactId>"
                + (version.isEmpty() ? "" : "<version>" + version + "</version>")
                + (artifact.equals("spring-ai-bom") ? "<type>pom</type><scope>import</scope>" : "") + "</dependency>";
    }
    private static String management(String dependency) { return "<dependencyManagement><dependencies>" + dependency + "</dependencies></dependencyManagement>"; }
}
