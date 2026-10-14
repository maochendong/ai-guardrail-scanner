package dev.aiguard.compat;

import com.google.gson.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Operator-owned semantic contracts, never read implicitly from a scanned repository. */
public final class BankPolicy {
  public static final String DATA = "BANK-DATA-001",
      IAM = "BANK-IAM-001",
      GUARD = "BANK-GUARD-001",
      FACTS = "BANK-CUST-001",
      SUITABILITY = "BANK-CUST-002",
      ACL = "BANK-INTERNAL-001",
      CAPABILITY = "BANK-INTERNAL-002";
  public final String profile, digest;
  private final Path source;
  private final Map<String, Contract> contracts;

  public static final class Contract {
    public final String symbol, kind, label, control, channel;
    public final int arity, arg, identity;
    public final List<Integer> args;
    public final boolean accept;

    private Contract(JsonObject o) throws IOException {
      symbol = string(o, "symbol");
      if (!symbol.matches(
              "[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)+(?:#[A-Za-z_$][A-Za-z0-9_$]*)?")
          || symbol.length() > 256) throw invalid();
      arity = integer(o, "arity", 0, 32);
      kind = one(o, "kind", "source", "transform", "check", "sink");
      Set<String> fields = new HashSet<String>(Arrays.asList("symbol", "arity", "kind"));
      String l = "", c = "", ch = "";
      int a = -1, i = -1;
      boolean accepted = true;
      List<Integer> slots = new ArrayList<Integer>();
      if ("source".equals(kind)) {
        fields.add("label");
        l =
            one(
                o,
                "label",
                "sensitive",
                "trusted-identity",
                "untrusted-identity",
                "model-output",
                "knowledge",
                "recommendation",
                "tool-input");
      } else if ("transform".equals(kind)) {
        fields.addAll(Arrays.asList("control", "arg"));
        c = one(o, "control", "redaction");
        a = integer(o, "arg", 0, arity - 1);
      } else {
        fields.add("args");
        JsonElement array = o.get("args");
        if (array == null || !array.isJsonArray() || array.getAsJsonArray().size() == 0)
          throw invalid();
        for (JsonElement slot : array.getAsJsonArray()) {
          int s = number(slot, 0, arity - 1);
          if (slots.contains(s)) throw invalid();
          slots.add(s);
        }
        if ("check".equals(kind)) {
          fields.addAll(Arrays.asList("control", "accept"));
          c = one(o, "control", "guard", "scope", "facts", "suitability", "doc-acl", "capability");
          JsonElement acceptElement = o.get("accept");
          if (acceptElement == null
              || !acceptElement.isJsonPrimitive()
              || !acceptElement.getAsJsonPrimitive().isBoolean()) throw invalid();
          accepted = acceptElement.getAsBoolean();
        } else {
          fields.add("channel");
          ch = one(o, "channel", "egress", "access", "release", "recommend", "retrieve", "tool");
          if (Arrays.asList("access", "recommend", "retrieve").contains(ch)) {
            fields.add("identity");
            i = integer(o, "identity", 0, arity - 1);
            if (slots.contains(i)) throw invalid();
          }
        }
      }
      keys(o, fields);
      label = l;
      control = c;
      channel = ch;
      arg = a;
      identity = i;
      accept = accepted;
      args = Collections.unmodifiableList(slots);
    }
  }

  private BankPolicy(String profile, String json, Path source) throws IOException {
    if (!Arrays.asList("generic", "bank-common", "bank-customer", "bank-internal", "bank-all")
        .contains(profile)) throw invalid();
    if (json.getBytes(StandardCharsets.UTF_8).length > 65536) throw invalid();
    JsonElement parsed = Json.parse(json);
    if (!parsed.isJsonObject()) throw invalid();
    JsonObject o = parsed.getAsJsonObject();
    keys(o, new HashSet<String>(Arrays.asList("version", "contracts")));
    if (integer(o, "version", 1, 1) != 1) throw invalid();
    JsonElement items = o.get("contracts");
    if (items == null || !items.isJsonArray() || items.getAsJsonArray().size() > 256)
      throw invalid();
    Map<String, Contract> loaded = new LinkedHashMap<String, Contract>();
    for (JsonElement item : items.getAsJsonArray()) {
      if (!item.isJsonObject()) throw invalid();
      Contract contract = new Contract(item.getAsJsonObject());
      if (loaded.put(contract.symbol + "/" + contract.arity, contract) != null) throw invalid();
    }
    if ("generic".equals(profile) && !loaded.isEmpty()) throw invalid();
    this.profile = profile;
    this.source = source;
    contracts = Collections.unmodifiableMap(loaded);
    try {
      byte[] hash =
          MessageDigest.getInstance("SHA-256")
              .digest(
                  (profile + "\n" + Json.COMPACT.toJson(parsed)).getBytes(StandardCharsets.UTF_8));
      StringBuilder out = new StringBuilder();
      for (byte b : hash) out.append(String.format(Locale.ROOT, "%02x", b & 255));
      digest = out.toString();
    } catch (java.security.NoSuchAlgorithmException error) {
      throw new IOException("POLICY_DIGEST_UNAVAILABLE");
    }
  }

  public static BankPolicy generic() {
    try {
      return parse("generic", "{\"version\":1,\"contracts\":[]}");
    } catch (IOException error) {
      throw new IllegalStateException(error);
    }
  }

  public static BankPolicy parse(String profile, String json) throws IOException {
    return new BankPolicy(profile, json, null);
  }

  public static BankPolicy load(String profile, Path file) throws IOException {
    if (file == null) return parse(profile, "{\"version\":1,\"contracts\":[]}");
    Path path = file.toAbsolutePath().normalize();
    PathPolicy.rejectLinks(path);
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) > 65536)
      throw invalid();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Set<OpenOption> options = new HashSet<OpenOption>();
    options.add(StandardOpenOption.READ);
    options.add(LinkOption.NOFOLLOW_LINKS);
    try (SeekableByteChannel channel = Files.newByteChannel(path, options);
        InputStream input = Channels.newInputStream(channel)) {
      byte[] buffer = new byte[4096];
      int count;
      while ((count = input.read(buffer)) >= 0) {
        if (out.size() + count > 65536) throw invalid();
        out.write(buffer, 0, count);
      }
    }
    String json =
        StandardCharsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(out.toByteArray()))
            .toString();
    return new BankPolicy(profile, json, path.toRealPath());
  }

  public void checkRepository(Path root) throws IOException {
    if (source != null && source.startsWith(root.toRealPath()))
      throw new IOException("POLICY_INSIDE_REPOSITORY");
  }

  public boolean enabled() {
    return !"generic".equals(profile);
  }

  public Contract contract(String symbol, int arity) {
    return contracts.get(symbol + "/" + arity);
  }

  public int contractCount() {
    return contracts.size();
  }

  public List<String> ruleIds() {
    List<String> ids = new ArrayList<String>();
    if (!enabled()) return ids;
    ids.addAll(Arrays.asList(DATA, IAM, GUARD));
    if ("bank-customer".equals(profile) || "bank-all".equals(profile))
      ids.addAll(Arrays.asList(FACTS, SUITABILITY));
    if ("bank-internal".equals(profile) || "bank-all".equals(profile))
      ids.addAll(Arrays.asList(ACL, CAPABILITY));
    return ids;
  }

  public Map<String, Object> metadata() {
    return Findings.map(
        "profile",
        profile,
        "version",
        "bank-policy-v1",
        "digest",
        digest,
        "contractCount",
        contracts.size(),
        "semantics",
        "operator-declared contracts; implementations not verified");
  }

  public static List<Map<String, Object>> catalog() {
    List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
    for (String id : Arrays.asList(DATA, IAM, GUARD, FACTS, SUITABILITY, ACL, CAPABILITY)) {
      out.add(
          Findings.map(
              "id",
              id,
              "domain",
              domain(id),
              "title",
              title(id),
              "severity",
              "HIGH",
              "profile",
              id.startsWith("BANK-CUST")
                  ? "bank-customer"
                  : id.startsWith("BANK-INTERNAL") ? "bank-internal" : "bank-common",
              "languages",
              Arrays.asList("java", "python"),
              "limitations",
              Arrays.asList(
                  "Operator semantic mappings required",
                  "Bounded local flow; no runtime certification")));
    }
    return out;
  }

  static String domain(String id) {
    return DATA.equals(id)
        ? "L3"
        : IAM.equals(id) || ACL.equals(id) || CAPABILITY.equals(id) ? "L2" : "L7";
  }

  static String title(String id) {
    if (DATA.equals(id)) return "银行敏感数据出站脱敏结果使用";
    if (IAM.equals(id)) return "可信身份与资源授权绑定";
    if (GUARD.equals(id)) return "Guard 拒绝与失败路径阻断";
    if (FACTS.equals(id)) return "客销事实与时效校验";
    if (SUITABILITY.equals(id)) return "客户身份与适当性校验绑定";
    if (ACL.equals(id)) return "行内检索文档权限校验";
    return "行内工具能力与参数授权";
  }

  private static void keys(JsonObject object, Set<String> allowed) throws IOException {
    for (Map.Entry<String, JsonElement> entry : object.entrySet())
      if (!allowed.contains(entry.getKey())) throw invalid();
    for (String key : allowed) if (!object.has(key)) throw invalid();
  }

  private static String string(JsonObject object, String key) throws IOException {
    JsonElement value = object.get(key);
    if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString())
      throw invalid();
    return value.getAsString();
  }

  private static String one(JsonObject o, String key, String... values) throws IOException {
    String result = string(o, key);
    if (!Arrays.asList(values).contains(result)) throw invalid();
    return result;
  }

  private static int integer(JsonObject o, String key, int min, int max) throws IOException {
    return number(o.get(key), min, max);
  }

  private static int number(JsonElement v, int min, int max) throws IOException {
    if (v == null || !v.isJsonPrimitive() || !v.getAsJsonPrimitive().isNumber()) throw invalid();
    try {
      int result = v.getAsBigDecimal().intValueExact();
      if (result < min || result > max) throw invalid();
      return result;
    } catch (ArithmeticException error) {
      throw invalid();
    }
  }

  private static IOException invalid() {
    return new IOException("INVALID_BANK_POLICY");
  }
}
