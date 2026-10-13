package dev.aiguard.analysis.rules;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.dataformat.yaml.*;
import dev.aiguard.analysis.SourceProject;
import dev.aiguard.model.ScanModel.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import org.yaml.snakeyaml.LoaderOptions;

/** Static application configuration declarations; never resolves environment variables or YAML tags. */
public final class ConfigurationRules {
    public static final Rule RULE = new Rule("AI-L3-002", Domain.L3, "原始内容观测配置",
        "检查 application*.properties/YAML 中五项 Spring AI 原始提示、响应和工具内容记录开关；只判断声明，不证明运行时生效。",
        "默认关闭原始内容记录；需要诊断时限制数据范围、脱敏、访问和保留时间，并核实实际运行环境覆盖。",
        List.of("https://docs.spring.io/spring-ai/reference/observability/index.html",
            "https://raw.githubusercontent.com/spring-projects/spring-ai/v1.0.0/spring-ai-docs/src/main/antora/modules/ROOT/pages/observability/index.adoc",
            "https://raw.githubusercontent.com/spring-projects/spring-ai/v1.1.0/spring-ai-docs/src/main/antora/modules/ROOT/pages/observability/index.adoc"));
    private static final Map<String, String> FLAGS = Map.of(
        "spring.ai.chat.client.observations.log-prompt", "聊天客户端提示内容",
        "spring.ai.chat.client.observations.log-completion", "聊天客户端响应内容",
        "spring.ai.chat.observations.log-prompt", "模型提示内容",
        "spring.ai.chat.observations.log-completion", "模型响应内容",
        "spring.ai.tools.observations.include-content", "工具参数与结果内容");
    private static final Map<String, String> CANONICAL = new TreeMap<>();
    private static final int MAX_CHARACTERS = 2 * 1024 * 1024;
    private static final int MAX_TOKENS = 100_000;
    private static final List<String> LIMITATIONS = List.of(
        "仅识别 application*.properties/yml/yaml 的五项明确开关，不推断其他观测或日志组件。",
        "环境变量、命令行、远程配置、profile 激活及实际配置优先级未求值；关闭声明也不证明运行时关闭。",
        "未运行应用，未验证记录是否生效、是否含敏感数据或是否已有脱敏；声明风险不等于真实泄露。",
        "仅接受字面量 true/false；重复键、占位符、YAML tag/anchor/alias、解析或预算失败均为 UNKNOWN。",
        "1.0.x 的客户端 log-completion 语义未确认；其余列明属性适用于已核实 1.0/1.1/2.0 正式版本系列。每种证据最多 40 个位置。");
    static { FLAGS.keySet().forEach(k -> CANONICAL.put(normalize(k), k)); }
    private ConfigurationRules() {}

    public static boolean hasAiConfiguration(Map<String, String> configurations) {
        for (var entry : configurations.entrySet()) {
            if (!application(entry.getKey())) continue;
            Parsed parsed = parse(entry.getKey(), entry.getValue(), () -> false);
            if (parsed.documents.stream().anyMatch(d -> d.values.keySet().stream().anyMatch(CANONICAL::containsKey))) return true;
        }
        return false;
    }
    public static List<Assessment> assess(SourceProject project, BooleanSupplier cancelled) {
        List<Evidence> enabled = new ArrayList<>(), disabled = new ArrayList<>(), unknown = new ArrayList<>();
        boolean found = false;
        for (var entry : new TreeMap<>(project.configurations()).entrySet()) {
            check(cancelled);
            String path = entry.getKey();
            if (!application(path)) continue;
            Parsed parsed = parse(path, entry.getValue(), cancelled);
            if (parsed.problem != null) {
                add(unknown, path, parsed.problemLine, parsed.problem);
                continue;
            }
            for (Document doc : parsed.documents) {
                for (var property : doc.values.entrySet()) {
                    check(cancelled);
                    String key = CANONICAL.get(property.getKey());
                    if (key == null) continue;
                    found = true;
                    Value value = property.getValue();
                    String label = FLAGS.get(key);
                    if (!supported(project, key)) {
                        add(unknown, path, value.line, "发现" + label + "配置，但当前版本对应属性语义未确认。");
                    } else if (doc.conditional || profileFile(path)) {
                        add(unknown, path, value.line, "发现" + label + "配置，但所属 profile 的激活条件未确定。");
                    } else if (value.literal == Literal.TRUE) {
                        add(enabled, path, value.line, "配置声明开启" + label + "记录，存在敏感暴露风险；运行时生效和脱敏未验证。");
                        add(unknown, path, value.line, "该内容记录声明的环境覆盖、运行时生效及脱敏状态尚未核实。");
                    } else if (value.literal == Literal.FALSE) {
                        add(disabled, path, value.line, "配置声明关闭" + label + "记录；仅观察到声明，不证明运行时关闭或整体安全。");
                        add(unknown, path, value.line, "该关闭声明可能被环境或其他配置源覆盖，实际运行值未核实。");
                    } else add(unknown, path, value.line, "发现" + label + "配置，但值不是可直接确认的字面量布尔值。");
                }
            }
        }
        List<Assessment> assessments = new ArrayList<>();
        if (!enabled.isEmpty()) assessments.add(result(Disposition.VIOLATED, Severity.MEDIUM,
            "发现明确开启原始 AI 内容记录的配置声明；这是静态配置风险，不是实际泄露证明。", enabled));
        if (!unknown.isEmpty()) assessments.add(result(Disposition.UNKNOWN, Severity.INFO,
            "存在未解析值、条件或配置生效范围；这些不确定性不因其他声明已识别而消除。", unknown));
        if (!disabled.isEmpty()) assessments.add(result(Disposition.OBSERVED, Severity.INFO,
            "发现关闭声明；仍需核实实际生效配置及其他记录路径。", disabled));
        if (assessments.isEmpty()) {
            boolean applicable = project.metadata().aiDetected() || found || !project.diagnostics().isEmpty();
            assessments.add(result(applicable ? Disposition.UNKNOWN : Disposition.NOT_APPLICABLE, Severity.INFO,
                applicable ? "未发现支持范围内的原始内容开关声明；无法证明日志与观测内容策略。" : "已解析配置中未发现本规则支持的 Spring AI 内容开关，项目也未识别相关 AI 证据。", List.of()));
        }
        return List.copyOf(assessments);
    }
    private static boolean supported(SourceProject project, String key) {
        if (!project.supportedVersion() || !project.metadata().springAiVersion().matches("(?:1\\.0|1\\.1|2\\.0)\\.\\d+")) return false;
        return !key.equals("spring.ai.chat.client.observations.log-completion") || !project.metadata().springAiVersion().startsWith("1.0.");
    }
    private static Assessment result(Disposition disposition, Severity severity, String explanation, List<Evidence> evidence) {
        return new Assessment(RULE.id(), RULE.domain(), disposition, severity, RULE.title(), explanation, RULE.recommendation(), evidence, LIMITATIONS);
    }
    private static void add(List<Evidence> list, String path, int line, String detail) {
        var evidence = new Evidence(path, Math.max(line, 1), detail);
        if (list.size() < 40 && !list.contains(evidence)) list.add(evidence);
    }
    private static boolean application(String path) { return path.substring(path.lastIndexOf('/') + 1).matches("application[^/]*\\.(?:properties|yaml|yml)"); }
    private static boolean profileFile(String path) { return path.substring(path.lastIndexOf('/') + 1).matches("application-.+\\.(?:properties|yaml|yml)"); }
    private static String normalize(String key) {
        return key.toLowerCase(Locale.ROOT).replace("-", "").replace("_", "");
    }
    private enum Literal { TRUE, FALSE, UNKNOWN }
    private record Value(Literal literal, int line) {}
    private record Document(Map<String, Value> values, boolean conditional) {}
    private record Parsed(List<Document> documents, String problem, int problemLine) {}
    private static Literal literal(String value) {
        if (value.trim().equalsIgnoreCase("true")) return Literal.TRUE;
        if (value.trim().equalsIgnoreCase("false")) return Literal.FALSE;
        return Literal.UNKNOWN;
    }
    private static Parsed parse(String path, String content, BooleanSupplier cancelled) {
        if (content.length() > MAX_CHARACTERS) return new Parsed(List.of(), "配置内容超过安全解析预算，未评估开关。", 1);
        try { return path.endsWith(".properties") ? properties(content, cancelled) : yaml(content, cancelled); }
        catch (CancellationException e) { throw e; }
        catch (ConfigurationException e) { return new Parsed(List.of(), e.getMessage(), e.line); }
        catch (IOException | RuntimeException e) { return new Parsed(List.of(), "配置无法安全解析或超出解析约束，未评估开关。", 1); }
    }
    private static Parsed properties(String content, BooleanSupplier cancelled) throws IOException {
        List<Document> documents = new ArrayList<>();
        Map<String, Value> values = new TreeMap<>();
        StringBuilder logical = new StringBuilder();
        int firstLine = 1, index = 0;
        for (String physical : content.split("\\r\\n|\\r|\\n", -1)) {
            check(cancelled);
            index++;
            if (index > MAX_TOKENS) throw new ConfigurationException("配置行数超过安全解析预算，未评估开关。", index);
            if (logical.isEmpty() && (physical.equals("#---") || physical.equals("!---"))) {
                documents.add(document(values)); values = new TreeMap<>(); continue;
            }
            if (logical.isEmpty()) {
                firstLine = index;
                String stripped = physical.stripLeading();
                if (stripped.isEmpty() || stripped.startsWith("#") || stripped.startsWith("!")) continue;
            }
            logical.append(physical).append('\n');
            int slashes = 0;
            for (int i = physical.length() - 1; i >= 0 && physical.charAt(i) == '\\'; i--) slashes++;
            if (slashes % 2 != 0) continue;
            Properties line = new Properties();
            line.load(new StringReader(logical.toString()));
            for (String key : line.stringPropertyNames()) {
                String normalized = normalize(key);
                if (values.putIfAbsent(normalized, new Value(literal(line.getProperty(key)), firstLine)) != null)
                    throw new ConfigurationException("配置含重复或等价属性键，优先级存在歧义，未评估该文件。", firstLine);
            }
            logical.setLength(0);
        }
        if (!logical.isEmpty()) throw new ConfigurationException("配置包含未完成的续行，未评估该文件。", firstLine);
        documents.add(document(values));
        return new Parsed(List.copyOf(documents), null, 1);
    }
    private static Document document(Map<String, Value> values) {
        return new Document(Map.copyOf(values), values.containsKey(normalize("spring.config.activate.on-profile")) || values.containsKey(normalize("spring.profiles")) || values.containsKey(normalize("spring.config.activate.on-cloud-platform")));
    }
    private static YAMLFactory factory() {
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        options.setMaxAliasesForCollections(0);
        options.setNestingDepthLimit(40);
        options.setCodePointLimit(MAX_CHARACTERS);
        return YAMLFactory.builder().loaderOptions(options)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(40).maxStringLength(100_000).maxNameLength(1024).maxNumberLength(64).build())
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();
    }
    private static Parsed yaml(String content, BooleanSupplier cancelled) throws IOException {
        YAMLFactory factory = factory();
        List<Map<String, Value>> locations = new ArrayList<>();
        Map<String, Value> location = null;
        int depth = 0, tokens = 0;
        // Preflight the event stream; never instantiate tagged Java types, expand aliases or execute content.
        try (YAMLParser parser = factory.createParser(content)) {
            JsonToken token;
            while ((token = parser.nextToken()) != null) {
                check(cancelled);
                if (++tokens > MAX_TOKENS) throw new ConfigurationException("YAML token 数超过安全解析预算，未评估该文件。", parser.currentTokenLocation().getLineNr());
                if (parser.getTypeId() != null || parser.getObjectId() != null || parser.isCurrentAlias())
                    throw new ConfigurationException("YAML 包含 tag、anchor 或 alias，本规则不求值此类构造。", parser.currentTokenLocation().getLineNr());
                if (token.isStructStart()) {
                    if (depth++ == 0) { location = new HashMap<>(); locations.add(location); }
                } else if (token.isStructEnd()) depth--;
                else if (token.isScalarValue() && location != null) {
                    String pointer = parser.getParsingContext().pathAsPointer().toString();
                    String key = normalize(pointer.startsWith("/") ? pointer.substring(1).replace('/', '.') : pointer);
                    Value original = new Value(literal(parser.getText()), parser.currentTokenLocation().getLineNr());
                    if (location.putIfAbsent(key, original) != null)
                        throw new ConfigurationException("YAML 含等价重复属性路径，优先级存在歧义，未评估该文件。", parser.currentTokenLocation().getLineNr());
                }
            }
        }
        ObjectMapper mapper = new ObjectMapper(factory).enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY);
        List<Document> documents = new ArrayList<>();
        try (JsonParser parser = factory.createParser(content)) {
            int doc = 0;
            while (parser.nextToken() != null) {
                check(cancelled);
                JsonNode tree = mapper.readTree(parser);
                if (tree == null || tree.isNull()) continue;
                if (!tree.isObject()) throw new ConfigurationException("YAML 文档根节点不是配置映射，未评估该文件。", 1);
                Map<String, Value> values = new TreeMap<>();
                flatten(tree, "", values, doc < locations.size() ? locations.get(doc) : Map.of(), cancelled);
                documents.add(document(values)); doc++;
            }
        }
        return new Parsed(List.copyOf(documents), null, 1);
    }
    private static void flatten(JsonNode node, String prefix, Map<String, Value> values, Map<String, Value> locations, BooleanSupplier cancelled) {
        check(cancelled);
        if (node.isObject() && !CANONICAL.containsKey(normalize(prefix))) {
            node.properties().forEach(entry -> flatten(entry.getValue(), prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey(), values, locations, cancelled));
        } else {
            String key = normalize(prefix);
            Value original = locations.getOrDefault(key, new Value(Literal.UNKNOWN, 1));
            Literal literal = node.isBoolean() || node.isTextual() ? original.literal : Literal.UNKNOWN;
            if (values.putIfAbsent(key, new Value(literal, original.line)) != null)
                throw new ConfigurationException("YAML 含等价重复属性路径，优先级存在歧义，未评估该文件。", original.line);
        }
    }
    private static void check(BooleanSupplier cancelled) { if (cancelled.getAsBoolean()) throw new CancellationException("scan cancelled"); }
    private static final class ConfigurationException extends RuntimeException {
        final int line;
        ConfigurationException(String message, int line) { super(message); this.line = line; }
    }
}
