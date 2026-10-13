package dev.aiguard.analysis;

import dev.aiguard.analysis.rules.ConfigurationRules;
import dev.aiguard.model.ScanModel.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CancellationException;
import static org.junit.jupiter.api.Assertions.*;

class ConfigurationRulesTest {
    private static final String PROMPT = "spring.ai.chat.observations.log-prompt";
    private static SourceProject project(Map<String,String> configs, String version, boolean ai) {
        return new SourceProject(Path.of("/configuration-fixture"),List.of(),configs,
            new ProjectMetadata(version, version.isEmpty()?"UNKNOWN":"SUPPORTED",0,configs.size(),ai),"digest",List.of());
    }
    private static List<Assessment> assess(String path,String text) {
        return ConfigurationRules.assess(project(Map.of(path,text),"1.1.6",true),()->false);
    }
    private static boolean has(List<Assessment> results, Disposition d) { return results.stream().anyMatch(a->a.disposition()==d); }
    @ParameterizedTest @ValueSource(strings={
        "spring.ai.chat.client.observations.log-prompt", "spring.ai.chat.client.observations.log-completion",
        "spring.ai.chat.observations.log-prompt", "spring.ai.chat.observations.log-completion", "spring.ai.tools.observations.include-content"})
    void eachPropertiesFlagDistinguishesEnabledDisabledAndUnknown(String key) {
        var enabled=assess("src/main/resources/application.properties",key+"=true");
        assertTrue(has(enabled,Disposition.VIOLATED));
        assertTrue(has(enabled,Disposition.UNKNOWN),"runtime overrides remain uncertain");
        var disabled=assess("application.properties",key+"=false");
        assertTrue(has(disabled,Disposition.OBSERVED)); assertFalse(has(disabled,Disposition.VIOLATED));
        var unknown=assess("application.properties",key+"=${PRIVATE_ENVIRONMENT_VALUE:true}");
        assertTrue(has(unknown,Disposition.UNKNOWN)); assertFalse(has(unknown,Disposition.VIOLATED));
        assertFalse(unknown.toString().contains("PRIVATE_ENVIRONMENT_VALUE"));
    }
    @ParameterizedTest @ValueSource(strings={
        "spring.ai.chat.client.observations.log-prompt", "spring.ai.chat.client.observations.log-completion",
        "spring.ai.chat.observations.log-prompt", "spring.ai.chat.observations.log-completion", "spring.ai.tools.observations.include-content"})
    void dottedYamlFlagsDistinguishThreeStates(String key) {
        assertTrue(has(assess("application.yaml",key+": true"),Disposition.VIOLATED));
        assertTrue(has(assess("application.yaml",key+": false"),Disposition.OBSERVED));
        var unknown=assess("application.yaml",key+": ${VALUE:false}");
        assertTrue(has(unknown,Disposition.UNKNOWN)); assertFalse(has(unknown,Disposition.VIOLATED));
    }
    @Test void nestedYamlHasExactSourceLocation() {
        String text="""
            spring:
              ai:
                chat:
                  observations:
                    log-prompt: true
            """;
        var results=assess("application.yml",text);
        assertTrue(has(results,Disposition.VIOLATED));
        assertEquals(5,results.stream().filter(a->a.disposition()==Disposition.VIOLATED).findFirst().orElseThrow().evidence().getFirst().line());
    }
    @Test void duplicatePropertiesDoNotUseLastValueAsProof() {
        var results=assess("application.properties",PROMPT+"=false\n"+PROMPT+"=true\n");
        assertTrue(has(results,Disposition.UNKNOWN)); assertFalse(has(results,Disposition.VIOLATED));
    }
    @Test void relaxedEquivalentPropertiesAreDuplicate() {
        var results=assess("application.properties",PROMPT+"=true\nspring.ai.chat.observations.logPrompt=false\n");
        assertTrue(has(results,Disposition.UNKNOWN)); assertFalse(has(results,Disposition.VIOLATED));
    }
    @Test void duplicateYamlKeysRemainUnknown() {
        var results=assess("application.yml",PROMPT+": false\n"+PROMPT+": true");
        assertTrue(has(results,Disposition.UNKNOWN)); assertFalse(has(results,Disposition.VIOLATED));
    }
    @Test void nestedAndDottedDuplicateYamlPathsRemainUnknown() {
        var results=assess("application.yml",PROMPT+": true\nspring:\n  ai:\n    chat:\n      observations:\n        log-prompt: false\n");
        assertTrue(has(results,Disposition.UNKNOWN)); assertFalse(has(results,Disposition.VIOLATED));
    }
    @Test void profileFilenameAndActivationAreUnresolved() {
        assertFalse(has(assess("application-prod.properties",PROMPT+"=true"),Disposition.VIOLATED));
        assertFalse(has(assess("application.yaml","spring.config.activate.on-profile: prod\n"+PROMPT+": true"),Disposition.VIOLATED));
        assertFalse(has(assess("application.properties","spring.config.activate.on-profile=prod\n"+PROMPT+"=true"),Disposition.VIOLATED));
    }
    @Test void multipleYamlDocumentsAreAllReadWithProfileScope() {
        var results=assess("application.yaml",PROMPT+": false\n---\nspring.config.activate.on-profile: prod\n"+PROMPT+": true\n");
        assertTrue(has(results,Disposition.OBSERVED)); assertTrue(has(results,Disposition.UNKNOWN)); assertFalse(has(results,Disposition.VIOLATED));
    }
    @Test void propertiesDocumentProfileDoesNotBleedIntoDefaultDocument() {
        var results=assess("application.properties",PROMPT+"=false\n#---\nspring.config.activate.on-profile=prod\n"+PROMPT+"=true\n");
        assertTrue(has(results,Disposition.OBSERVED)); assertTrue(has(results,Disposition.UNKNOWN)); assertFalse(has(results,Disposition.VIOLATED));
    }
    @Test void allSupportedMajorFamiliesAndClientCompletionBoundary() {
        for(String version:List.of("1.0.0","1.1.0","2.0.1"))
            assertTrue(has(ConfigurationRules.assess(project(Map.of("application.properties",PROMPT+"=true"),version,true),()->false),Disposition.VIOLATED));
        assertFalse(has(ConfigurationRules.assess(project(Map.of("application.properties","spring.ai.chat.client.observations.log-completion=true"),"1.0.9",true),()->false),Disposition.VIOLATED));
        assertFalse(has(ConfigurationRules.assess(project(Map.of("application.properties",PROMPT+"=true"),"1.0.0-M1",true),()->false),Disposition.VIOLATED));
    }
    @Test void unknownVersionCannotBecomeConfigurationViolation() {
        var result=ConfigurationRules.assess(project(Map.of("application.properties",PROMPT+"=true"),"",true),()->false);
        assertTrue(has(result,Disposition.UNKNOWN)); assertFalse(has(result,Disposition.VIOLATED));
    }
    @Test void configurationOnlyRecognitionIncludesFalseAndPlaceholderButNotComments() {
        assertTrue(ConfigurationRules.hasAiConfiguration(Map.of("application.properties",PROMPT+"=false")));
        assertTrue(ConfigurationRules.hasAiConfiguration(Map.of("application.yml",PROMPT+": ${VALUE:false}")));
        assertFalse(ConfigurationRules.hasAiConfiguration(Map.of("application.properties","# "+PROMPT+"=true")));
        assertFalse(ConfigurationRules.hasAiConfiguration(Map.of("example.properties",PROMPT+"=true")));
        assertFalse(ConfigurationRules.hasAiConfiguration(Map.of("application.yaml","unrelated: true")));
    }
    @Test void yamlJavaTagIsNotConstructedAndValueIsNotReported() throws Exception {
        Path marker=Files.createTempDirectory("yaml-tag-test").resolve("must-not-exist");
        String text="!!java.lang.ProcessBuilder [touch, "+marker+"]\n";
        var results=assess("application.yaml",text);
        assertTrue(has(results,Disposition.UNKNOWN)); assertFalse(has(results,Disposition.VIOLATED));
        assertFalse(Files.exists(marker)); assertFalse(results.toString().contains(marker.toString()));
    }
    @Test void yamlAnchorsAliasesAndRecursiveAliasesStayUnknown() {
        for(String text:List.of("enable: &flag true\n"+PROMPT+": *flag", "loop: &loop [*loop]\n"+PROMPT+": true")) {
            var results=assess("application.yaml",text);
            assertTrue(has(results,Disposition.UNKNOWN)); assertFalse(has(results,Disposition.VIOLATED));
        }
    }
    @Test void malformedYamlAndDeepYamlDoNotReportPartialSuccess() {
        for(String text:List.of(PROMPT+": true\nbroken: [", "key: ".repeat(100)+"true")) {
            var results=assess("application.yaml",text);
            assertTrue(has(results,Disposition.UNKNOWN)); assertFalse(has(results,Disposition.VIOLATED));
        }
    }
    @Test void propertiesContinuationAndUnicodeKeyEscapeHaveCorrectStartLine() {
        var results=assess("application.properties","# header\nspring.ai.chat.observations.log-\\u0070rompt=tr\\\n  ue\n");
        assertTrue(has(results,Disposition.VIOLATED));
        assertEquals(2,results.getFirst().evidence().getFirst().line());
    }
    @Test void arbitraryOrStructuredValuesAreUnknown() {
        for(String value:List.of("1", "[true]", "{enabled: true}", "null", "maybe", "yes", "no", "on", "off")) {
            var results=assess("application.yml",PROMPT+": "+value);
            assertTrue(has(results,Disposition.UNKNOWN)); assertFalse(has(results,Disposition.VIOLATED));
        }
    }
    @Test void scanCancellationAndCatalogIntegration() {
        assertThrows(CancellationException.class,()->ConfigurationRules.assess(project(Map.of("application.yml",PROMPT+": true"),"1.1.6",true),()->true));
        assertEquals(11,new RuleEngine().catalog().size());
        assertTrue(new RuleEngine().assess(project(Map.of("application.properties",PROMPT+"=true"),"1.1.6",true),()->false).stream()
            .anyMatch(a->a.ruleId().equals("AI-L3-002")&&a.disposition()==Disposition.VIOLATED));
    }
}
