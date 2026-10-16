package dev.aiguard.compat;

import dev.aiguard.compat.grammar.JavaLexer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.antlr.v4.runtime.ANTLRInputStream;
import org.antlr.v4.runtime.Token;

/** Source-only eligibility for default Lombok summaries, never an annotation processor. */
final class LombokSourceDefaults {
  static final int BLOCKED = 0, CANDIDATE = 1, DEFAULTS = 2;
  private final Map<String, SourceFile> sources = new HashMap<String, SourceFile>();
  private final Map<String, List<String>> annotations = new HashMap<String, List<String>>();
  private final List<SourceFile> configs = new ArrayList<SourceFile>();
  private final java.util.Set<String> declaredAnnotations = new java.util.HashSet<String>();
  private final Cancel cancel;
  private boolean processingDisabled;

  LombokSourceDefaults(List<SourceFile> files, Cancel cancel) {
    this.cancel = cancel;
    for (SourceFile file : files) {
      cancel.check();
      sources.put(file.path, file);
      if (file.path.endsWith(".java")
          && file.content.contains("interface")
          && file.content.contains("@")) {
        List<String> forms = annotationForms(file);
        annotations.put(file.path, forms);
        for (String form : forms)
          if (form.startsWith("<type>:")) declaredAnnotations.add(form.substring(7));
      }
      if (file.path.equals("lombok.config") || file.path.endsWith("/lombok.config"))
        configs.add(file);
      if (file.path.endsWith("pom.xml")
          || file.path.endsWith(".gradle")
          || file.path.endsWith(".gradle.kts")
          || file.path.endsWith("gradle.properties")) {
        String compact = file.content.replaceAll("\\s+", "");
        if (compact.contains("-proc:none")
            || compact.contains("<proc>none</proc>")
            || compact.contains("<maven.compiler.proc>none</maven.compiler.proc>"))
          processingDisabled = true;
      }
    }
  }

  boolean shadowsAnnotation(JavaSyntax.Node context, String expected) {
    String simple = expected.substring(expected.lastIndexOf('.') + 1);
    String same =
        context.unit.packageName.isEmpty() ? simple : context.unit.packageName + "." + simple;
    if (declaredAnnotations.contains(expected) || declaredAnnotations.contains(same)) return true;
    List<String> forms = annotations.get(context.unit.path);
    return forms != null && forms.contains("<local>:" + simple);
  }

  int qualification(JavaSyntax.Type type, JavaGraph graph) {
    SourceFile source = sources.get(type.node.unit.path);
    if (source == null || processingDisabled || type.node.unit.syntaxErrors > 0) return BLOCKED;
    List<String> forms = annotations.get(source.path);
    if (forms == null) {
      forms = annotationForms(source);
      annotations.put(source.path, forms);
    }
    for (String form : forms) {
      cancel.check();
      if (form.equals("<unavailable>")) return BLOCKED;
      boolean parameters = form.endsWith("(");
      String name = parameters ? form.substring(0, form.length() - 1) : form;
      String qualified = graph.qualifiedType(type.node, name);
      if (qualified.startsWith("lombok.")
          && !qualified.equals("lombok.Data")
          && !qualified.equals("lombok.Getter")
          && !qualified.equals("lombok.Setter")
          && !qualified.equals("lombok.NonNull")) return BLOCKED;
      if (parameters
          && (qualified.equals("lombok.Data")
              || qualified.equals("lombok.Getter")
              || qualified.equals("lombok.Setter"))) return BLOCKED;
    }
    String directory = directory(source.path);
    while (true) {
      for (SourceFile config : configs) {
        cancel.check();
        if (!directory(config.path).equals(directory)) continue;
        boolean stop = false;
        boolean declared = false;
        for (String raw : config.content.split("\\r?\\n")) {
          String line = raw.trim();
          if (line.isEmpty() || line.startsWith("#")) continue;
          if (line.matches("config\\.stopBubbling\\s*=\\s*(true|false)")) {
            if (declared) return BLOCKED;
            declared = true;
            stop = line.endsWith("true");
          } else return BLOCKED;
        }
        if (stop) return DEFAULTS;
      }
      if (directory.isEmpty()) return CANDIDATE;
      directory = directory(directory);
    }
  }

  String simpleLoopExit(JavaSyntax.Node statement) {
    SourceFile source = sources.get(statement.unit.path);
    if (source == null || statement.start < 0 || statement.end > source.content.length()) return "";
    String text = source.content.substring(statement.start, statement.end);
    if (text.matches("\\s*continue\\s*;\\s*")) return "CONTINUE";
    if (text.matches("\\s*break\\s*;\\s*")) return "BREAK";
    return "";
  }

  private List<String> annotationForms(SourceFile source) {
    List<String> forms = new ArrayList<String>();
    List<Token> tokens = new ArrayList<Token>();
    JavaLexer lexer = new JavaLexer(new ANTLRInputStream(source.content));
    lexer.removeErrorListeners();
    for (int count = 0; ; count++) {
      cancel.check();
      if (count > 200000) {
        forms.add("<unavailable>");
        return forms;
      }
      Token token = lexer.nextToken();
      if (token.getType() == Token.EOF) break;
      if (token.getChannel() == Token.DEFAULT_CHANNEL) tokens.add(token);
    }
    for (int i = 0; i + 1 < tokens.size(); i++) {
      cancel.check();
      if (!tokens.get(i).getText().equals("@")) continue;
      if (tokens.get(i + 1).getText().equals("interface") && i + 2 < tokens.size()) {
        String simple = tokens.get(i + 2).getText();
        StringBuilder packageName = new StringBuilder();
        for (int p = 0; p < tokens.size(); p++) {
          if (!tokens.get(p).getText().equals("package")) continue;
          while (++p < tokens.size() && !tokens.get(p).getText().equals(";"))
            packageName.append(tokens.get(p).getText());
          break;
        }
        forms.add("<type>:" + (packageName.length() == 0 ? "" : packageName + ".") + simple);
        forms.add("<local>:" + simple);
        continue;
      }
      StringBuilder name = new StringBuilder(tokens.get(++i).getText());
      while (i + 2 < tokens.size() && tokens.get(i + 1).getText().equals(".")) {
        name.append('.').append(tokens.get(i + 2).getText());
        i += 2;
      }
      if (i + 2 < tokens.size()
          && tokens.get(i + 1).getText().equals("(")
          && !tokens.get(i + 2).getText().equals(")")) name.append('(');
      forms.add(name.toString());
    }
    return forms;
  }

  private static String directory(String path) {
    int slash = path.lastIndexOf('/');
    return slash < 0 ? "" : path.substring(0, slash);
  }
}
