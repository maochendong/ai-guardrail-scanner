package dev.aiguard.compat;

import java.io.StringReader;
import java.util.*;
import java.util.regex.*;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.*;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.events.*;
import org.yaml.snakeyaml.nodes.*;

/**
 * Literal, offline build and application configuration. No interpolation or external resolution.
 */
final class LegacyConfiguration {
  private final Cancel cancel;
  private final Map<String, Version> modules = new LinkedHashMap<String, Version>();
  final List<Map<String, Object>> diagnostics = new ArrayList<Map<String, Object>>();
  boolean aiDetected;
  String version = "UNKNOWN", status = "UNKNOWN";
  private static final Set<String> FLAGS =
      new HashSet<String>(
          Arrays.asList(
              norm("spring.ai.chat.client.observations.log-prompt"),
              norm("spring.ai.chat.client.observations.log-completion"),
              norm("spring.ai.chat.observations.log-prompt"),
              norm("spring.ai.chat.observations.log-completion"),
              norm("spring.ai.tools.observations.include-content")));

  private static final class Version {
    final Set<String> versions = new LinkedHashSet<String>();
    boolean ai, unresolved;
  }

  LegacyConfiguration(List<SourceFile> files, Cancel cancel) {
    this.cancel = cancel;
    Map<String, SourceFile> configs = new LinkedHashMap<String, SourceFile>();
    Map<String, Pom> poms = new LinkedHashMap<String, Pom>();
    for (SourceFile file : files) {
      cancel.check();
      configs.put(file.path, file);
      if (basename(file.path).equals("pom.xml"))
        try {
          poms.put(file.path, parsePom(file));
        } catch (java.util.concurrent.CancellationException error) {
          throw error;
        } catch (Exception error) {
          diagnostics.add(
              Findings.diagnostic(
                  "BUILD_PARSE_ERROR",
                  file.path,
                  "Build file could not be parsed safely; version remains unknown."));
        }
    }
    for (SourceFile file : files) {
      cancel.check();
      String name = basename(file.path);
      if (!name.equals("pom.xml")
          && !name.equals("build.gradle")
          && !name.equals("build.gradle.kts")) continue;
      Version value = name.equals("pom.xml") ? pom(file, poms) : gradle(file, configs);
      String dir = directory(file.path);
      Version previous = modules.get(dir);
      if (previous != null) {
        value.versions.addAll(previous.versions);
        value.ai |= previous.ai;
        value.unresolved |= previous.unresolved;
      }
      modules.put(dir, value);
      aiDetected |= value.ai;
    }
    Set<String> known = new LinkedHashSet<String>();
    boolean unresolved = false;
    for (Version value : modules.values())
      if (value.ai) {
        known.addAll(value.versions);
        unresolved |= value.unresolved;
      }
    if (known.size() == 1 && !unresolved) {
      version = known.iterator().next();
      status = supportedVersion(version) ? "SUPPORTED" : "UNSUPPORTED";
    } else if (known.size() > 1) status = "CONFLICT";
  }

  boolean supported(String path) {
    return supportedVersion(versionFor(path));
  }

  String versionFor(String path) {
    Version best = null;
    int length = -1;
    for (Map.Entry<String, Version> entry : modules.entrySet())
      if ((entry.getKey().length() == 0 || path.startsWith(entry.getKey() + "/"))
          && entry.getKey().length() > length) {
        best = entry.getValue();
        length = entry.getKey().length();
      }
    return best != null && !best.unresolved && best.versions.size() == 1
        ? best.versions.iterator().next()
        : "UNKNOWN";
  }

  private static final class Dependency {
    String group, artifact, version;
    boolean managed, conditional, bom;
  }

  private static final class Pom {
    final Map<String, String> properties = new HashMap<String, String>();
    final List<Dependency> dependencies = new ArrayList<Dependency>();
    String parentPath, group, artifact, version, parentGroup, parentArtifact, parentVersion;
  }

  private Version pom(SourceFile file, Map<String, Pom> poms) {
    Version result = new Version();
    Pom own = poms.get(file.path);
    if (own == null) {
      result.unresolved = true;
      return result;
    }
    List<Pom> chain = new ArrayList<Pom>();
    Set<String> visited = new HashSet<String>();
    String current = file.path;
    while (current != null && visited.add(current) && chain.size() < 32) {
      cancel.check();
      Pom item = poms.get(current);
      if (item == null) break;
      chain.add(0, item);
      if (item.parentPath == null) break;
      java.nio.file.Path dir = java.nio.file.Paths.get(current).getParent();
      java.nio.file.Path target =
          (dir == null ? java.nio.file.Paths.get(item.parentPath) : dir.resolve(item.parentPath))
              .normalize();
      current = target.toString().replace('\\', '/');
      if (current.startsWith("../") || target.isAbsolute()) break;
      Pom parent = poms.get(current);
      if (parent == null
          || !parent.group.equals(item.parentGroup)
          || !parent.artifact.equals(item.parentArtifact)
          || !parent.version.equals(resolve(item.parentVersion, item.properties))) break;
    }
    Map<String, String> properties = new HashMap<String, String>();
    for (Pom item : chain) properties.putAll(item.properties);
    Map<String, String> managed = new HashMap<String, String>();
    List<String> boms = new ArrayList<String>();
    for (Pom item : chain)
      for (Dependency dep : item.dependencies) {
        cancel.check();
        if (!resolve(dep.group, properties).equals("org.springframework.ai") || dep.conditional)
          continue;
        if (dep.bom) boms.add(resolve(dep.version, properties));
        if (dep.managed && dep.version.length() > 0)
          managed.put(dep.artifact, resolve(dep.version, properties));
      }
    for (Dependency dep : own.dependencies) {
      cancel.check();
      if (!resolve(dep.group, properties).equals("org.springframework.ai")) continue;
      result.ai = true;
      if (dep.conditional) result.unresolved = true;
      String version = resolve(dep.version, properties);
      if (version.length() > 0) addVersion(result, version);
      else if (managed.containsKey(dep.artifact)) addVersion(result, managed.get(dep.artifact));
      else if (!boms.isEmpty()) for (String bom : boms) addVersion(result, bom);
      else result.unresolved = true;
    }
    return result;
  }

  private void addVersion(Version result, String value) {
    if (value.matches("[0-9]+\\.[0-9]+\\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?"))
      result.versions.add(value);
    else result.unresolved = true;
  }

  private Pom parsePom(SourceFile file) throws Exception {
    cancel.check();
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    factory.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
    builder.setErrorHandler(new DefaultHandler());
    Document doc = builder.parse(new InputSource(new StringReader(file.content)));
    boundedXml(doc);
    Element project = doc.getDocumentElement();
    if (!local(project).equals("project")) throw new IllegalArgumentException();
    Pom result = new Pom();
    Element props = childElement(project, "properties");
    if (props != null)
      for (org.w3c.dom.Node n = props.getFirstChild(); n != null; n = n.getNextSibling())
        if (n instanceof Element) result.properties.put(local(n), n.getTextContent().trim());
    Element parent = childElement(project, "parent");
    result.parentGroup = parent == null ? "" : child(parent, "groupId");
    result.parentArtifact = parent == null ? "" : child(parent, "artifactId");
    result.parentVersion = parent == null ? "" : child(parent, "version");
    result.group = child(project, "groupId");
    if (result.group.length() == 0) result.group = result.parentGroup;
    result.artifact = child(project, "artifactId");
    result.version = child(project, "version");
    if (result.version.length() == 0) result.version = result.parentVersion;
    result.properties.put("project.version", result.version);
    result.properties.put("pom.version", result.version);
    result.properties.put("project.parent.version", result.parentVersion);
    result.version = resolve(result.version, result.properties);
    result.parentPath =
        parent == null
            ? null
            : childElement(parent, "relativePath") == null
                ? "../pom.xml"
                : child(parent, "relativePath");
    if ("".equals(result.parentPath)) result.parentPath = null;
    NodeList deps = project.getElementsByTagNameNS("*", "dependency");
    if (deps.getLength() > 10000) throw new IllegalArgumentException();
    for (int i = 0; i < deps.getLength(); i++) {
      cancel.check();
      Element node = (Element) deps.item(i);
      if (ancestor(node, "plugin")) continue;
      Dependency dep = new Dependency();
      dep.group = child(node, "groupId");
      dep.artifact = child(node, "artifactId");
      dep.version = child(node, "version");
      dep.managed = ancestor(node, "dependencyManagement");
      dep.conditional = ancestor(node, "profile");
      dep.bom =
          dep.managed
              && dep.artifact.equals("spring-ai-bom")
              && child(node, "scope").equals("import")
              && child(node, "type").equals("pom");
      result.dependencies.add(dep);
    }
    return result;
  }

  private static final class XmlDepth {
    final org.w3c.dom.Node node;
    final int depth;

    XmlDepth(org.w3c.dom.Node node, int depth) {
      this.node = node;
      this.depth = depth;
    }
  }

  private void boundedXml(Document document) {
    ArrayDeque<XmlDepth> pending = new ArrayDeque<XmlDepth>();
    pending.add(new XmlDepth(document, 0));
    int count = 0;
    while (!pending.isEmpty()) {
      cancel.check();
      XmlDepth current = pending.removeLast();
      if (current.depth > 128 || ++count > 100000) throw new IllegalArgumentException();
      for (org.w3c.dom.Node child = current.node.getFirstChild();
          child != null;
          child = child.getNextSibling()) pending.add(new XmlDepth(child, current.depth + 1));
    }
  }

  private static String local(org.w3c.dom.Node node) {
    return node.getLocalName() == null ? node.getNodeName() : node.getLocalName();
  }

  private static boolean ancestor(org.w3c.dom.Node n, String name) {
    for (n = n.getParentNode(); n != null; n = n.getParentNode())
      if (name.equals(local(n))) return true;
    return false;
  }

  private static Element childElement(Element n, String key) {
    for (org.w3c.dom.Node p = n.getFirstChild(); p != null; p = p.getNextSibling())
      if (p instanceof Element && key.equals(local(p))) return (Element) p;
    return null;
  }

  private static String child(Element n, String key) {
    Element value = childElement(n, key);
    return value == null ? "" : value.getTextContent().trim();
  }

  private Version gradle(SourceFile file, Map<String, SourceFile> configs) {
    Version result = new Version();
    String source = stripComments(file.content);
    Map<String, String> properties = new HashMap<String, String>();
    SourceFile propFile =
        configs.get(
            directory(file.path).length() == 0
                ? "gradle.properties"
                : directory(file.path) + "/gradle.properties");
    if (propFile != null)
      try {
        Properties parsed = new Properties();
        parsed.load(new StringReader(propFile.content));
        for (String key : parsed.stringPropertyNames())
          properties.put(key, parsed.getProperty(key));
      } catch (Exception error) {
        result.unresolved = true;
      }
    Matcher assignment =
        Pattern.compile(
                "(?m)(?:^|[;{\\n"
                    + "])\\s*(?:(?:val|var|def)\\s+|ext\\.)?([A-Za-z_][A-Za-z0-9_.-]*)\\s*=\\s*(['\"])([^'\"\\r"
                    + "\\n"
                    + "]*)\\2")
            .matcher(source);
    while (assignment.find()) properties.put(assignment.group(1), assignment.group(3));
    Matcher extra =
        Pattern.compile(
                "(?:extra|ext)\\s*\\[\\s*['\"]([^'\"]+)['\"]\\s*]\\s*=\\s*['\"]([^'\"]+)['\"]")
            .matcher(source);
    while (extra.find()) properties.put(extra.group(1), extra.group(2));
    Matcher byExtra =
        Pattern.compile("(?:val|var)\\s+(\\w+)\\s+by\\s+extra\\(\\s*['\"]([^'\"]+)['\"]\\s*\\)")
            .matcher(source);
    while (byExtra.find()) properties.put(byExtra.group(1), byExtra.group(2));
    Matcher all =
        Pattern.compile(
                "(?m)(?:^|[;{\\n"
                    + "])\\s*(?:(?:val|var|def)\\s+|ext\\.)?([A-Za-z_][A-Za-z0-9_.-]*)\\s*=\\s*([^\\r"
                    + "\\n"
                    + ";}]*)")
            .matcher(source);
    while (all.find())
      if (!all.group(2).trim().matches("(['\"])[^'\"]*\\1")) properties.remove(all.group(1));
    Matcher coordinate =
        Pattern.compile(
                "(?:api|implementation|compileOnly|runtimeOnly|annotationProcessor|platform|enforcedPlatform|mavenBom)\\s*\\(?\\s*(['\"])(org\\.springframework\\.ai):([A-Za-z0-9_.-]+)(?::([^'\"\\r"
                    + "\\n"
                    + "]*))?\\1")
            .matcher(source);
    boolean found = false, bom = false, unmanaged = false;
    while (coordinate.find()) {
      cancel.check();
      found = true;
      result.ai = true;
      String version = coordinate.group(4);
      if (coordinate.group(3).equals("spring-ai-bom")
          && version != null
          && coordinate.group().matches("(?s)(?:platform|enforcedPlatform|mavenBom).*")) bom = true;
      if (version == null || version.trim().length() == 0) unmanaged = true;
      else addVersion(result, resolve(version, properties));
    }
    if (unmanaged && !bom) result.unresolved = true;
    if (source.contains("org.springframework.ai") && !found) {
      result.ai = true;
      result.unresolved = true;
      diagnostics.add(
          Findings.diagnostic(
              "GRADLE_VERSION_UNRESOLVED",
              file.path,
              "Computed Gradle declarations are not evaluated; version remains unknown."));
    }
    return result;
  }

  private static String resolve(String value, Map<String, String> properties) {
    Pattern pattern = Pattern.compile("\\$\\{([^{}]+)}|\\$([A-Za-z_][A-Za-z0-9_]*)");
    Set<String> seen = new HashSet<String>();
    for (int i = 0; i < 16 && seen.add(value); i++) {
      if (value.length() > 4096) return "__UNRESOLVED__";
      Matcher matcher = pattern.matcher(value);
      StringBuffer out = new StringBuffer();
      boolean changed = false;
      while (matcher.find()) {
        String replacement =
            properties.get(matcher.group(1) == null ? matcher.group(2) : matcher.group(1));
        if (replacement == null) replacement = matcher.group();
        else changed = true;
        if (replacement.length() > 4096 || out.length() + replacement.length() > 4096)
          return "__UNRESOLVED__";
        matcher.appendReplacement(out, Matcher.quoteReplacement(replacement));
      }
      matcher.appendTail(out);
      value = out.toString();
      if (!changed) break;
    }
    return value.trim();
  }

  private static String stripComments(String input) {
    StringBuilder out = new StringBuilder();
    char quote = 0;
    for (int i = 0; i < input.length(); i++) {
      char c = input.charAt(i);
      if (quote != 0) {
        out.append(c);
        if (c == '\\' && i + 1 < input.length()) out.append(input.charAt(++i));
        else if (c == quote) quote = 0;
      } else if (c == '\'' || c == '\"') {
        quote = c;
        out.append(c);
      } else if (c == '/' && i + 1 < input.length() && input.charAt(i + 1) == '/') {
        while (i < input.length() && input.charAt(i) != '\n') {
          out.append(' ');
          i++;
        }
        if (i < input.length()) out.append('\n');
      } else if (c == '/' && i + 1 < input.length() && input.charAt(i + 1) == '*') {
        i += 2;
        while (i < input.length()
            && !(input.charAt(i) == '*' && i + 1 < input.length() && input.charAt(i + 1) == '/')) {
          out.append(input.charAt(i) == '\n' ? '\n' : ' ');
          i++;
        }
        i++;
      } else out.append(c);
    }
    return out.toString();
  }

  static boolean supportedVersion(String value) {
    return value.matches("(?:1\\.0|1\\.1|2\\.0)\\.[0-9]+");
  }

  void assess(List<SourceFile> files, Cancel cancel, JavaAnalysis.Bucket bucket) {
    for (SourceFile file : files) {
      cancel.check();
      if (!basename(file.path).matches("application[^/]*\\.(properties|ya?ml)")) continue;
      try {
        if (file.content.length() > 2 * 1024 * 1024) throw new IllegalArgumentException();
        List<Map<String, Value>> docs =
            file.path.endsWith(".properties")
                ? properties(file.content, cancel)
                : yaml(file.content, cancel);
        for (Map<String, Value> doc : docs) {
          boolean conditional =
              basename(file.path).startsWith("application-")
                  || doc.containsKey(norm("spring.profiles"))
                  || doc.containsKey(norm("spring.config.activate.on-profile"))
                  || doc.containsKey(norm("spring.config.activate.on-cloud-platform"));
          for (Map.Entry<String, Value> entry : doc.entrySet()) {
            if (!FLAGS.contains(entry.getKey())) continue;
            aiDetected = true;
            Value value = entry.getValue();
            if (versionFor(file.path).equals("UNKNOWN")) status = "UNKNOWN";
            boolean semantic =
                supported(file.path)
                    && !(entry
                            .getKey()
                            .equals(norm("spring.ai.chat.client.observations.log-completion"))
                        && versionFor(file.path).startsWith("1.0."));
            if (!semantic
                || conditional
                || !("true".equalsIgnoreCase(value.literal)
                    || "false".equalsIgnoreCase(value.literal)))
              bucket.add("UNKNOWN", file.path, value.line, "原始内容开关的版本语义、激活条件或字面量值未确定。");
            else {
              bucket.add(
                  "true".equalsIgnoreCase(value.literal) ? "VIOLATED" : "OBSERVED",
                  file.path,
                  value.line,
                  "true".equalsIgnoreCase(value.literal)
                      ? "配置声明开启原始 AI 内容记录；运行时生效和实际敏感暴露尚未验证。"
                      : "配置声明关闭原始 AI 内容记录；仅观察到声明。");
              bucket.add("UNKNOWN", file.path, value.line, "环境、命令行、远程配置覆盖与运行时生效值未验证。");
            }
          }
        }
      } catch (java.util.concurrent.CancellationException e) {
        throw e;
      } catch (Exception error) {
        bucket.add("UNKNOWN", file.path, 1, "配置无法安全解析，含重复键、标签、别名或超过解析预算；该文件开关未评估。");
      }
    }
  }

  private static final class Value {
    final String literal;
    final int line;

    Value(String s, int l) {
      literal = s;
      line = l;
    }
  }

  private static List<Map<String, Value>> properties(String text, Cancel cancel) throws Exception {
    List<Map<String, Value>> docs = new ArrayList<Map<String, Value>>();
    Map<String, Value> values = new LinkedHashMap<String, Value>();
    StringBuilder logical = new StringBuilder();
    int index = 0, first = 1;
    for (String physical : text.split("\\r\\n|\\r|\\n", -1)) {
      cancel.check();
      index++;
      if (index > 100000) throw new IllegalArgumentException();
      if (logical.length() == 0 && (physical.equals("#---") || physical.equals("!---"))) {
        docs.add(values);
        values = new LinkedHashMap<String, Value>();
        continue;
      }
      if (logical.length() == 0) {
        first = index;
        if (physical.trim().length() == 0
            || physical.trim().startsWith("#")
            || physical.trim().startsWith("!")) continue;
      }
      logical.append(physical).append('\n');
      int slash = 0;
      for (int j = physical.length() - 1; j >= 0 && physical.charAt(j) == '\\'; j--) slash++;
      if (slash % 2 != 0) continue;
      Properties parsed = new Properties();
      parsed.load(new StringReader(logical.toString()));
      for (String key : parsed.stringPropertyNames()) {
        String normalized = norm(key);
        if (values.containsKey(normalized)) throw new IllegalArgumentException();
        values.put(normalized, new Value(parsed.getProperty(key).trim(), first));
      }
      logical.setLength(0);
    }
    if (logical.length() != 0) throw new IllegalArgumentException();
    docs.add(values);
    return docs;
  }

  private static List<Map<String, Value>> yaml(String text, Cancel cancel) {
    LoaderOptions options = new LoaderOptions();
    options.setAllowDuplicateKeys(false);
    options.setMaxAliasesForCollections(0);
    options.setNestingDepthLimit(40);
    options.setCodePointLimit(2 * 1024 * 1024);
    Yaml parser = new Yaml(options);
    int count = 0;
    for (Event event : parser.parse(new StringReader(text))) {
      cancel.check();
      if (++count > 100000) throw new IllegalArgumentException();
      if (event instanceof AliasEvent
          || event instanceof NodeEvent && ((NodeEvent) event).getAnchor() != null)
        throw new IllegalArgumentException();
      if (event instanceof ScalarEvent && ((ScalarEvent) event).getTag() != null
          || event instanceof CollectionStartEvent
              && ((CollectionStartEvent) event).getTag() != null)
        throw new IllegalArgumentException();
    }
    List<Map<String, Value>> docs = new ArrayList<Map<String, Value>>();
    for (org.yaml.snakeyaml.nodes.Node node : parser.composeAll(new StringReader(text))) {
      Map<String, Value> values = new LinkedHashMap<String, Value>();
      flatten(node, "", values, cancel, 0);
      docs.add(values);
    }
    return docs;
  }

  private static void flatten(
      org.yaml.snakeyaml.nodes.Node node,
      String prefix,
      Map<String, Value> values,
      Cancel cancel,
      int depth) {
    cancel.check();
    if (depth > 40) throw new IllegalArgumentException();
    if (node instanceof MappingNode) {
      Set<String> seen = new HashSet<String>();
      for (NodeTuple tuple : ((MappingNode) node).getValue()) {
        if (!(tuple.getKeyNode() instanceof ScalarNode)) throw new IllegalArgumentException();
        String key = ((ScalarNode) tuple.getKeyNode()).getValue();
        if (!seen.add(norm(key))) throw new IllegalArgumentException();
        flatten(
            tuple.getValueNode(),
            prefix.length() == 0 ? key : prefix + "." + key,
            values,
            cancel,
            depth + 1);
      }
    } else if (node instanceof ScalarNode) {
      String key = norm(prefix);
      if (values.containsKey(key)) throw new IllegalArgumentException();
      values.put(
          key, new Value(((ScalarNode) node).getValue().trim(), node.getStartMark().getLine() + 1));
    } else if (node instanceof SequenceNode) {
      if (FLAGS.contains(norm(prefix)))
        values.put(norm(prefix), new Value("", node.getStartMark().getLine() + 1));
    } else throw new IllegalArgumentException();
  }

  private static String norm(String s) {
    return s.toLowerCase(Locale.ROOT).replace("-", "").replace("_", "");
  }

  private static String directory(String path) {
    int slash = path.lastIndexOf('/');
    return slash < 0 ? "" : path.substring(0, slash);
  }

  private static String basename(String path) {
    return path.substring(path.lastIndexOf('/') + 1);
  }
}
