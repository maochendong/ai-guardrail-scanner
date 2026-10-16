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
public final class BusinessPolicy {
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

  public final int version;
  private final Map<String, Receiver> receivers;
  private final Set<String> sourceDigests;

  public static final class Receiver {
    public final String owner, field, type, assurance;

    private Receiver(JsonObject o) throws IOException {
      fields(o, set("owner", "field", "type", "assurance"), set("owner", "field", "type"));
      owner = symbol(o, "owner", false);
      field = identifier(string(o, "field"));
      type = symbol(o, "type", false);
      assurance = optionalOne(o, "assurance", "reviewed", "reviewed", "candidate");
    }
  }

  public static final class Contract {
    public final String symbol, kind, label, control, channel;
    public final String assurance,
        failureMode,
        mode,
        boundary,
        requiresLabel,
        scope,
        decisionSymbol;
    public final int arity, arg, identity, decisionArg;
    public final List<Integer> args, outboundArgs;
    public final List<String> parameterNames, valuePath;
    public final Map<String, Object> defaults;
    public final boolean accept;

    /** Optional constant argument discriminator for a call sink, never a name heuristic. */
    public final int whenArg;

    public final Object whenEquals;

    private Contract(JsonObject o, int version) throws IOException {
      symbol = symbol(o, "symbol", version == 2);
      arity = integer(o, "arity", 0, 32);
      kind = one(o, "kind", "source", "transform", "check", "sink");
      Set<String> allowed = set("symbol", "arity", "kind");
      Set<String> required = set("symbol", "arity", "kind");
      String l = "",
          c = "",
          ch = "",
          aLevel = "reviewed",
          failure = "closed",
          checkMode = "boolean",
          edge = "call",
          needs = "",
          dataScope = "restricted",
          decision = "";
      int a = -1, i = -1, decisionSlot = -1;
      int conditionArg = -1;
      Object conditionValue = null;
      boolean accepted = true;
      List<Integer> slots = new ArrayList<Integer>(), outbound = new ArrayList<Integer>();
      List<String> names = new ArrayList<String>(), path = new ArrayList<String>();
      Map<String, Object> defaultValues = new LinkedHashMap<String, Object>();
      if (version == 2) {
        allowed.addAll(set("assurance", "parameterNames", "defaults"));
        aLevel = optionalOne(o, "assurance", "reviewed", "reviewed", "candidate");
        failure = "unknown";
        dataScope = "unknown";
        if (o.has("parameterNames")) {
          JsonArray array = array(o.get("parameterNames"));
          if (array.size() != arity) throw invalid();
          for (JsonElement value : array) {
            String name = identifier(text(value));
            if (names.contains(name)) throw invalid();
            names.add(name);
          }
        }
        if (o.has("defaults")) {
          if (!o.has("parameterNames") || !o.get("defaults").isJsonObject()) throw invalid();
          for (Map.Entry<String, JsonElement> value : o.getAsJsonObject("defaults").entrySet()) {
            if (!names.contains(value.getKey())) throw invalid();
            defaultValues.put(value.getKey(), scalar(value.getValue()));
          }
        }
      }
      if ("source".equals(kind)) {
        allowed.add("label");
        required.add("label");
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
        if (version == 2) {
          allowed.add("outboundArgs");
          if (o.has("outboundArgs")) outbound = slots(o.get("outboundArgs"), arity - 1, true);
        }
      } else if ("transform".equals(kind)) {
        allowed.addAll(set("control", "arg"));
        required.addAll(set("control", "arg"));
        c =
            version == 1
                ? one(o, "control", "redaction")
                : one(o, "control", "redaction", "preserve");
        a = integer(o, "arg", version == 2 && "preserve".equals(c) ? -1 : 0, arity - 1);
      } else {
        allowed.add("args");
        required.add("args");
        if ("check".equals(kind)) {
          allowed.addAll(set("control", "accept"));
          required.add("control");
          c = one(o, "control", "guard", "scope", "facts", "suitability", "doc-acl", "capability");
          if (version == 2) {
            allowed.addAll(set("failureMode", "mode", "decision"));
            failure = optionalOne(o, "failureMode", "unknown", "closed", "open", "unknown");
            checkMode = optionalOne(o, "mode", "boolean", "boolean", "normal-return");
            if (o.has("decision")) {
              if (!"boolean".equals(checkMode) || !o.get("decision").isJsonObject())
                throw invalid();
              JsonObject choice = o.getAsJsonObject("decision");
              keys(choice, set("symbol", "arg"));
              decision = symbol(choice, "symbol", false);
              decisionSlot = integer(choice, "arg", -1, 0);
            }
          }
          if (version == 1 || "boolean".equals(checkMode)) required.add("accept");
          if (o.has("accept")) {
            JsonElement value = o.get("accept");
            if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean())
              throw invalid();
            accepted = value.getAsBoolean();
            if ("normal-return".equals(checkMode) && !accepted) throw invalid();
          }
          slots = slots(o.get("args"), arity - 1, false);
        } else {
          allowed.add("channel");
          required.add("channel");
          ch = one(o, "channel", "egress", "access", "release", "recommend", "retrieve", "tool");
          if (version == 2) {
            allowed.addAll(set("boundary", "requiresLabel", "valuePath", "scope", "when"));
            edge = optionalOne(o, "boundary", "call", "call", "return", "yield");
            dataScope = optionalOne(o, "scope", "unknown", "restricted", "public", "unknown");
            if (o.has("requiresLabel"))
              needs =
                  one(
                      o,
                      "requiresLabel",
                      "sensitive",
                      "trusted-identity",
                      "untrusted-identity",
                      "model-output",
                      "knowledge",
                      "recommendation",
                      "tool-input");
            if (o.has("valuePath")) {
              JsonArray elements = array(o.get("valuePath"));
              if (elements.size() > 16) throw invalid();
              for (JsonElement element : elements) {
                String name = text(element);
                if (name.length() == 0 || name.length() > 128) throw invalid();
                path.add(name);
              }
            }
            if (o.has("when")) {
              if (!"call".equals(edge) || !o.get("when").isJsonObject()) throw invalid();
              JsonObject condition = o.getAsJsonObject("when");
              keys(condition, set("arg", "equals"));
              conditionArg = integer(condition, "arg", 0, arity - 1);
              conditionValue = scalar(condition.get("equals"));
            }
          }
          int max = "call".equals(edge) ? arity - 1 : arity;
          boolean empty =
              version == 2
                  && arity == 0
                  && "call".equals(edge)
                  && ("access".equals(ch) || "retrieve".equals(ch));
          slots = slots(o.get("args"), max, empty);
          if (Arrays.asList("access", "recommend", "retrieve").contains(ch)) {
            allowed.add("identity");
            required.add("identity");
            i = integer(o, "identity", version == 2 ? -1 : 0, max);
            if (i >= 0 && slots.contains(i)) throw invalid();
          }
        }
      }
      fields(o, allowed, required);
      label = l;
      control = c;
      channel = ch;
      arg = a;
      identity = i;
      accept = accepted;
      whenArg = conditionArg;
      whenEquals = conditionValue;
      assurance = aLevel;
      failureMode = failure;
      mode = checkMode;
      boundary = edge;
      requiresLabel = needs;
      scope = dataScope;
      decisionSymbol = decision;
      decisionArg = decisionSlot;
      args = Collections.unmodifiableList(slots);
      outboundArgs = Collections.unmodifiableList(outbound);
      parameterNames = Collections.unmodifiableList(names);
      valuePath = Collections.unmodifiableList(path);
      defaults = Collections.unmodifiableMap(defaultValues);
    }
  }

  private BusinessPolicy(String profile, String json, Path source) throws IOException {
    if (!Arrays.asList("generic", "bank-common", "bank-customer", "bank-internal", "bank-all")
        .contains(profile)) throw invalid();
    if (json.getBytes(StandardCharsets.UTF_8).length > 65536) throw invalid();
    JsonElement parsed;
    try {
      parsed = Json.parse(json);
    } catch (IOException error) {
      throw invalid();
    } catch (IllegalArgumentException error) {
      throw invalid();
    }
    if (!parsed.isJsonObject()) throw invalid();
    JsonObject o = parsed.getAsJsonObject();
    version = integer(o, "version", 1, 2);
    if (version == 1) keys(o, set("version", "contracts"));
    else fields(o, set("version", "contracts", "receivers", "sourceDigests"), set("version"));
    JsonArray items = o.has("contracts") ? array(o.get("contracts")) : new JsonArray();
    if (items.size() > 256) throw invalid();
    Map<String, Contract> loaded = new LinkedHashMap<String, Contract>();
    for (JsonElement item : items) {
      if (!item.isJsonObject()) throw invalid();
      Contract contract = new Contract(item.getAsJsonObject(), version);
      if (loaded.put(contract.symbol + "/" + contract.arity, contract) != null) throw invalid();
    }
    Map<String, Receiver> receiverBindings = new LinkedHashMap<String, Receiver>();
    if (o.has("receivers")) {
      JsonArray bindings = array(o.get("receivers"));
      if (bindings.size() > 128) throw invalid();
      for (JsonElement binding : bindings) {
        if (!binding.isJsonObject()) throw invalid();
        Receiver receiver = new Receiver(binding.getAsJsonObject());
        if (receiverBindings.put(receiver.owner + "#" + receiver.field, receiver) != null)
          throw invalid();
      }
    }
    Set<String> boundDigests = new LinkedHashSet<String>();
    if (o.has("sourceDigests")) {
      JsonArray hashes = array(o.get("sourceDigests"));
      if (hashes.size() > 16 || hashes.size() == 0) throw invalid();
      for (JsonElement hash : hashes) {
        String value = text(hash);
        if (!value.matches("[0-9a-f]{64}") || !boundDigests.add(value)) throw invalid();
      }
    }
    this.profile = profile;
    this.source = source;
    contracts = Collections.unmodifiableMap(loaded);
    receivers = Collections.unmodifiableMap(receiverBindings);
    sourceDigests = Collections.unmodifiableSet(boundDigests);
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

  public static BusinessPolicy generic() {
    try {
      return parse("generic", "{\"version\":1,\"contracts\":[]}");
    } catch (IOException error) {
      throw new IllegalStateException(error);
    }
  }

  public static BusinessPolicy parse(String profile, String json) throws IOException {
    return new BusinessPolicy(profile, json, null);
  }

  public static BusinessPolicy load(String profile, Path file) throws IOException {
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
    return new BusinessPolicy(profile, json, path.toRealPath());
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

  public List<Contract> contractsForSymbol(String symbol) {
    List<Contract> found = new ArrayList<Contract>();
    for (Contract contract : contracts.values())
      if (contract.symbol.equals(symbol)) found.add(contract);
    return Collections.unmodifiableList(found);
  }

  public Receiver receiver(String owner, String field) {
    return receivers.get(owner + "#" + field);
  }

  public boolean matchesSourceDigest(String digest) {
    return sourceDigests.isEmpty() || sourceDigests.contains(digest);
  }

  public Collection<Contract> allContracts() {
    return Collections.unmodifiableCollection(contracts.values());
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

  static List<String> semanticRuleIds() {
    return Arrays.asList(DATA, IAM, GUARD, FACTS, SUITABILITY, ACL, CAPABILITY);
  }

  public Map<String, Object> metadata() {
    return Findings.map(
        "profile",
        profile,
        "version",
        "bank-policy-v" + version,
        "digest",
        digest,
        "contractCount",
        contracts.size(),
        "receiverCount",
        receivers.size(),
        "bindingCount",
        contracts.size() + receivers.size(),
        "sourceDigestCount",
        sourceDigests.size(),
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
    fields(object, allowed, allowed);
  }

  private static void fields(JsonObject object, Set<String> allowed, Set<String> required)
      throws IOException {
    for (Map.Entry<String, JsonElement> entry : object.entrySet())
      if (!allowed.contains(entry.getKey())) throw invalid();
    for (String key : required) if (!object.has(key)) throw invalid();
  }

  private static Set<String> set(String... keys) {
    return new HashSet<String>(Arrays.asList(keys));
  }

  private static JsonArray array(JsonElement value) throws IOException {
    if (value == null || !value.isJsonArray()) throw invalid();
    return value.getAsJsonArray();
  }

  private static String text(JsonElement value) throws IOException {
    if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString())
      throw invalid();
    return value.getAsString();
  }

  private static String identifier(String value) throws IOException {
    if (!value.matches("[A-Za-z_$][A-Za-z0-9_$]*") || value.length() > 128) throw invalid();
    return value;
  }

  private static String symbol(JsonObject object, String key, boolean constructor)
      throws IOException {
    String value = string(object, key);
    String member =
        constructor ? "(?:[A-Za-z_$][A-Za-z0-9_$]*|<init>)" : "[A-Za-z_$][A-Za-z0-9_$]*";
    if (!value.matches(
            "[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)+(?:#" + member + ")?")
        || value.length() > 256) throw invalid();
    return value;
  }

  private static Object scalar(JsonElement value) throws IOException {
    if (value.isJsonNull()) return null;
    if (!value.isJsonPrimitive()) throw invalid();
    JsonPrimitive primitive = value.getAsJsonPrimitive();
    if (primitive.isBoolean()) return primitive.getAsBoolean();
    if (primitive.isString()) return primitive.getAsString();
    if (primitive.isNumber()) {
      try {
        return primitive.getAsBigDecimal();
      } catch (NumberFormatException error) {
        throw invalid();
      }
    }
    throw invalid();
  }

  private static List<Integer> slots(JsonElement value, int max, boolean empty) throws IOException {
    JsonArray items = array(value);
    if (!empty && items.size() == 0 || items.size() > 33) throw invalid();
    List<Integer> out = new ArrayList<Integer>();
    for (JsonElement item : items) {
      int slot = number(item, 0, max);
      if (out.contains(slot)) throw invalid();
      out.add(slot);
    }
    return out;
  }

  private static String optionalOne(JsonObject o, String key, String fallback, String... values)
      throws IOException {
    return o.has(key) ? one(o, key, values) : fallback;
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
    } catch (NumberFormatException error) {
      throw invalid();
    }
  }

  private static IOException invalid() {
    return new IOException("INVALID_BANK_POLICY");
  }
}
