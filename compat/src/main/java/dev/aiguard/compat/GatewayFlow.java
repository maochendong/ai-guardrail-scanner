package dev.aiguard.compat;

import dev.aiguard.compat.JavaSyntax.*;
import java.util.*;

/** Model-protocol discovery and bounded value evidence. No target code or network is executed. */
public final class GatewayFlow {
  public static final class Origin {
    public final boolean candidate;
    public final List<Map<String, Object>> evidence;
    private final Set<Node> dependencies;

    Origin(boolean candidate, List<Map<String, Object>> evidence, Set<Node> dependencies) {
      this.candidate = candidate;
      this.evidence = Collections.unmodifiableList(evidence);
      this.dependencies = dependencies;
    }
  }

  private final JavaGraph graph;
  private final Cancel cancel;
  private final List<Method> gateways = new ArrayList<Method>();
  private final Set<Method> participants = new LinkedHashSet<Method>();
  private final Set<String> protocols = new LinkedHashSet<String>();
  private final List<Map<String, Object>> diagnostics = new ArrayList<Map<String, Object>>();
  private final List<Node> calls = new ArrayList<Node>();
  private final Map<Node, Origin> sources = new IdentityHashMap<Node, Origin>(),
      parameters = new IdentityHashMap<Node, Origin>();
  private final Map<Method, Origin> returns = new IdentityHashMap<Method, Origin>();
  private final Map<Method, Set<Integer>> callbacks = new IdentityHashMap<Method, Set<Integer>>();
  private final Map<Method, Map<Integer, Set<Integer>>> callbackValues =
      new IdentityHashMap<Method, Map<Integer, Set<Integer>>>();
  private final Set<Type> eventOwners =
      Collections.newSetFromMap(new IdentityHashMap<Type, Boolean>());
  private final Map<Method, List<Node>> writes = new IdentityHashMap<Method, List<Node>>(),
      methodCalls = new IdentityHashMap<Method, List<Node>>();
  private final Set<Node> envelopes =
      Collections.newSetFromMap(new IdentityHashMap<Node, Boolean>());
  private int budget = 600000;
  private boolean exhausted;
  private static final Set<String> METADATA =
      new HashSet<String>(
          Arrays.asList(
              "usage",
              "prompt_tokens",
              "completion_tokens",
              "total_tokens",
              "model",
              "id",
              "created",
              "finish_reason",
              "object",
              "system_fingerprint"));

  private GatewayFlow(JavaGraph graph, Cancel cancel) {
    this.graph = graph;
    this.cancel = cancel;
    for (Method method : graph.methods()) {
      cancel.check();
      List<Node> local = new ArrayList<Node>();
      for (Node call : JavaSyntax.find(method.rootNode, "CALL"))
        if (call.method == method) local.add(call);
      calls.addAll(local);
      methodCalls.put(method, local);
      writes.put(method, JavaSyntax.find(method.rootNode, "ASSIGN"));
    }
  }

  public static GatewayFlow build(JavaGraph graph, Cancel cancel) {
    cancel.check();
    GatewayFlow flow = new GatewayFlow(graph, cancel);
    flow.discover();
    flow.propagate();
    return flow;
  }

  public List<Method> gateways() {
    return Collections.unmodifiableList(gateways);
  }

  public Set<Method> participatingMethods() {
    return Collections.unmodifiableSet(participants);
  }

  public Set<String> protocols() {
    return Collections.unmodifiableSet(protocols);
  }

  public List<Map<String, Object>> diagnostics() {
    return Collections.unmodifiableList(diagnostics);
  }

  public Origin origin(Node expression) {
    if (expression == null || envelope(expression, 0)) return null;
    return value(expression, 0, identity());
  }

  public boolean isInvocation(Node call) {
    if (sources.containsKey(call)) return true;
    for (Method target : graph.resolve(call).targets)
      if (gateways.contains(target) || returns.containsKey(target) || callbacks.containsKey(target))
        return true;
    return false;
  }

  private static Set<Node> identity() {
    return Collections.newSetFromMap(new IdentityHashMap<Node, Boolean>());
  }

  private boolean tick() {
    cancel.check();
    if (--budget >= 0) return true;
    if (!exhausted) {
      exhausted = true;
      diagnostics.add(
          Findings.diagnostic(
              "GATEWAY_FLOW_BUDGET",
              "",
              "Gateway flow reached its operation budget; unresolved sources remain unknown."));
    }
    return false;
  }

  private Origin at(Node node, String detail) {
    return new Origin(
        false,
        Collections.singletonList(Findings.evidence(node.unit.path, node.line, detail)),
        identity());
  }

  private Origin candidate(Origin origin) {
    return origin == null ? null : new Origin(true, origin.evidence, origin.dependencies);
  }

  private Origin merge(Origin a, Origin b, boolean uncertain) {
    if (a == null) return uncertain ? candidate(b) : b;
    if (b == null) return uncertain ? candidate(a) : a;
    List<Map<String, Object>> evidence = new ArrayList<Map<String, Object>>(a.evidence);
    for (Map<String, Object> item : b.evidence)
      if (evidence.size() < 16 && !evidence.contains(item)) evidence.add(item);
    Set<Node> dependencies = identity();
    dependencies.addAll(a.dependencies);
    dependencies.addAll(b.dependencies);
    return new Origin(uncertain || a.candidate || b.candidate, evidence, dependencies);
  }

  private boolean same(Origin a, Origin b) {
    return a == b
        || a != null
            && b != null
            && a.candidate == b.candidate
            && a.evidence.equals(b.evidence)
            && a.dependencies.equals(b.dependencies);
  }

  private boolean put(Map<Node, Origin> map, Node node, Origin origin) {
    Origin next = merge(map.get(node), origin, false), old = map.put(node, next);
    return !same(old, next);
  }

  private void discover() {
    for (Method method : graph.methods()) {
      if (!tick()) break;
      boolean found = false;
      for (Node call : methodCalls.get(method)) {
        if (!tick()) break;
        if (call.name.equals("execute")
            && call.receiver != null
            && call.receiver.kind.equals("CALL")
            && call.receiver.name.equals("newCall")
            && call.receiver.args.size() == 1
            && typed(call.receiver.receiver, "okhttp3.OkHttpClient")
            && knownRequest(call.receiver.args.get(0))) {
          sources.put(
              call,
              at(call, "Typed HTTP execution receives a response from a model-protocol endpoint."));
          envelopes.add(call);
          found = true;
        }
        if (restResponse(call) || jdkResponse(call)) {
          sources.put(
              call,
              at(
                  call,
                  "Typed HTTP transport and associated request/response protocol identify model"
                      + " response data."));
          found = true;
          if (jdkResponse(call)) envelopes.add(call);
        }
        if (call.name.equals("newEventSource")
            && call.args.size() == 2
            && eventFactory(call.receiver)
            && knownRequest(call.args.get(0))) {
          found = true;
          Node listener = unfold(call.args.get(1), 0);
          if (listener != null
              && listener.kind.equals("NEW")
              && graph
                  .qualifiedType(listener, listener.type)
                  .equals("okhttp3.sse.EventSourceListener")) {
            for (Node type : listener.children)
              if (type.kind.equals("TYPE") && type.ownerType != null)
                for (Method event : type.ownerType.methods) {
                  if (!event.name.equals("onEvent")
                      || event.params.size() != 4
                      || !graph
                          .qualifiedType(event.node, event.params.get(0).type)
                          .equals("okhttp3.sse.EventSource")) continue;
                  boolean strings = true;
                  for (int i = 1; i < 4; i++)
                    strings &=
                        graph
                            .qualifiedType(event.node, event.params.get(i).type)
                            .equals("java.lang.String");
                  if (!strings) continue;
                  eventOwners.add(event.owner);
                  parameters.put(
                      event.params.get(3).node,
                      at(call, "Typed model event callback supplies the response frame."));
                  for (Node accept : methodCalls.get(event))
                    if (accept.name.equals("accept")
                        && (accept.args.size() == 1 || accept.args.size() == 2)) {
                      Node binding = graph.declaration(accept.receiver);
                      for (int i = 0; i < method.params.size(); i++)
                        if (method.params.get(i).node == binding) {
                          String consumer = graph.qualifiedType(binding, method.params.get(i).type);
                          if (!(consumer.equals("java.util.function.Consumer")
                                  && accept.args.size() == 1
                              || consumer.equals("java.util.function.BiConsumer")
                                  && accept.args.size() == 2)) continue;
                          for (int value = 0; value < accept.args.size(); value++)
                            if (origin(accept.args.get(value)) != null) {
                              callback(method).add(i);
                              callbackValues(method, i).add(value);
                            }
                        }
                    }
                }
          }
        }
      }
      if (found) {
        gateways.add(method);
        participants.add(method);
        protocols.add("openai-chat-compatible");
      }
    }
  }

  private Set<Integer> callback(Method method) {
    Set<Integer> indices = callbacks.get(method);
    if (indices == null) {
      indices = new LinkedHashSet<Integer>();
      callbacks.put(method, indices);
    }
    return indices;
  }

  private Set<Integer> callbackValues(Method method, int index) {
    Map<Integer, Set<Integer>> all = callbackValues.get(method);
    if (all == null) {
      all = new LinkedHashMap<Integer, Set<Integer>>();
      callbackValues.put(method, all);
    }
    Set<Integer> values = all.get(index);
    if (values == null) {
      values = new LinkedHashSet<Integer>();
      all.put(index, values);
    }
    return values;
  }

  private boolean typed(Node node, String expected) {
    return node != null && expected.equals(graph.declaredType(node));
  }

  private boolean staticType(Node node, String expected) {
    return node != null
        && graph.declaration(node) == null
        && expected.equals(graph.qualifiedType(node, JavaSyntax.name(node)));
  }

  private boolean knownRequest(Node expression) {
    Node request = unfold(expression, 0);
    if (request == null || !request.kind.equals("CALL")) return false;
    boolean post = false, endpoint = false;
    int depth = 0;
    Node cursor = request;
    while (cursor != null && cursor.kind.equals("CALL") && depth++ < 32) {
      if (cursor.name.equals("post") && cursor.args.size() == 1) post = true;
      if (cursor.name.equals("url") && cursor.args.size() == 1 && endpoint(cursor.args.get(0), 0))
        endpoint = true;
      cursor = unfold(cursor.receiver, 0);
    }
    return post
        && endpoint
        && cursor != null
        && cursor.kind.equals("NEW")
        && graph.qualifiedType(cursor, cursor.type).equals("okhttp3.Request.Builder");
  }

  private boolean eventFactory(Node node) {
    Node expression = unfold(node, 0);
    return typed(node, "okhttp3.sse.EventSource.Factory")
        || expression != null
            && expression.kind.equals("CALL")
            && expression.name.equals("createFactory")
            && expression.args.size() == 1
            && staticType(expression.receiver, "okhttp3.sse.EventSources")
            && typed(expression.args.get(0), "okhttp3.OkHttpClient");
  }

  private boolean restResponse(Node call) {
    if (!call.name.equals("body")
        || call.args.size() != 1
        || !call.args.get(0).kind.equals("CLASS")) return false;
    boolean retrieve = false, post = false, endpoint = false;
    Node payload = null;
    int depth = 0;
    for (Node c = call.receiver; c != null && depth++ < 32; c = c.receiver) {
      if (!c.kind.equals("CALL")) break;
      if (c.name.equals("retrieve")) retrieve = true;
      if (c.name.equals("post") && typed(c.receiver, "org.springframework.web.client.RestClient"))
        post = true;
      if (c.name.equals("uri") && !c.args.isEmpty() && endpoint(c.args.get(0), 0)) endpoint = true;
      if (c.name.equals("body") && c.args.size() == 1) payload = unfold(c.args.get(0), 0);
    }
    if (!retrieve || !post) return false;
    if (endpoint) return true;
    if (payload == null || !payload.kind.equals("NEW")) return false;
    Type request = type(graph.qualifiedType(payload, payload.type)),
        response = type(graph.qualifiedType(call.args.get(0), call.args.get(0).type));
    return has(request, "model", "messages")
        && has(element(request, "messages"), "role", "content")
        && has(response, "choices")
        && has(element(response, "choices"), "message")
        && has(element(element(response, "choices"), "message"), "content");
  }

  private boolean jdkResponse(Node call) {
    if (!call.name.equals("send")
        || call.args.size() != 2
        || !typed(call.receiver, "java.net.http.HttpClient")) return false;
    Node request = unfold(call.args.get(0), 0);
    boolean post = false, endpoint = false, root = false;
    int depth = 0;
    for (Node c = request; c != null && depth++ < 32; c = c.receiver)
      if (c.kind.equals("CALL")) {
        if (c.name.equals("POST")) post = true;
        if (c.name.equals("uri") && c.args.size() == 1 && uriEndpoint(c.args.get(0)))
          endpoint = true;
        if (c.name.equals("newBuilder") && staticType(c.receiver, "java.net.http.HttpRequest")) {
          root = true;
          if (c.args.size() == 1 && uriEndpoint(c.args.get(0))) endpoint = true;
        }
      }
    Node handler = call.args.get(1);
    return root
        && post
        && endpoint
        && handler.kind.equals("CALL")
        && handler.name.equals("ofString")
        && staticType(handler.receiver, "java.net.http.HttpResponse.BodyHandlers");
  }

  private boolean uriEndpoint(Node expr) {
    Node value = unfold(expr, 0);
    return endpoint(value, 0)
        || value != null
            && value.kind.equals("CALL")
            && value.name.equals("create")
            && staticType(value.receiver, "java.net.URI")
            && value.args.size() == 1
            && endpoint(value.args.get(0), 0);
  }

  private Type type(String qualified) {
    Type found = null;
    for (Unit unit : graph.units)
      for (Type type : unit.types)
        if (type.qualifiedName.equals(qualified)) {
          if (found != null) return null;
          found = type;
        }
    return found;
  }

  private boolean has(Type type, String... names) {
    if (type == null) return false;
    for (String name : names) {
      boolean found = false;
      for (Node field : type.fields) if (field.name.equals(name)) found = true;
      if (!found) return false;
    }
    return true;
  }

  private Type element(Type type, String name) {
    if (type == null) return null;
    for (Node field : type.fields)
      if (field.name.equals(name)) {
        String raw = field.type;
        int open = raw.indexOf('<'), close = raw.lastIndexOf('>');
        if (open >= 0 && close > open) {
          raw = raw.substring(open + 1, close);
          if (raw.indexOf(',') >= 0) return null;
        }
        return type(graph.qualifiedType(field, raw));
      }
    return null;
  }

  private boolean endpoint(Node expression, int depth) {
    if (expression == null || depth > 12 || !tick()) return false;
    Node node = unfold(expression, 0);
    if (node == null) return false;
    if (node.kind.equals("LITERAL") && node.literalValue != null)
      return node.literalValue.matches(".*?/chat/completions/?(?:\\?.*)?");
    if (node.kind.equals("BINARY") && node.name.equals("+"))
      for (Node arg : node.args) if (endpoint(arg, depth + 1)) return true;
    return false;
  }

  private void propagate() {
    boolean changed = false;
    for (int round = 0; round < 10 && !exhausted; round++) {
      changed = false;
      for (Method method : graph.methods()) {
        if (!tick()) break;
        Origin merged = null;
        boolean missing = false;
        for (Node ret : JavaSyntax.find(method.rootNode, "RETURN"))
          if (ret.method == method && !ret.args.isEmpty()) {
            Origin found = origin(ret.args.get(0));
            if (found == null) missing = true;
            else merged = merge(merged, found, false);
          }
        if (merged != null) {
          if (missing) merged = candidate(merged);
          Origin old = returns.put(method, merged);
          changed |= !same(old, merged);
        }
      }
      for (Node call : calls) {
        if (!tick()) break;
        JavaGraph.Edge edge = graph.resolve(call);
        for (Method target : edge.targets) {
          for (int i = 0; i < Math.min(call.args.size(), target.params.size()); i++) {
            Origin source = origin(call.args.get(i));
            if (source != null) {
              Set<Node> dependencies = identity();
              dependencies.add(target.params.get(i).node);
              source = new Origin(true, source.evidence, dependencies);
              changed |= put(parameters, target.params.get(i).node, source);
            }
          }
          Set<Integer> indices = callbacks.get(target);
          if (indices != null)
            for (Integer i : new ArrayList<Integer>(indices))
              if (i < call.args.size()) {
                Node argument = unfold(call.args.get(i), 0);
                Origin source =
                    at(
                        call,
                        "Source-local gateway supplies a model-output callback; dispatch remains"
                            + " source evidence.");
                if (edge.candidate) source = candidate(source);
                if (argument != null && argument.kind.equals("LAMBDA")) {
                  for (Integer value : callbackValues(target, i))
                    if (value < argument.params.size())
                      changed |=
                          put(parameters, argument.params.get(value).node, candidate(source));
                } else if (argument != null
                    && argument.kind.equals("NAME")
                    && call.method != null) {
                  Node decl = graph.declaration(argument);
                  for (int j = 0; j < call.method.params.size(); j++)
                    if (call.method.params.get(j).node == decl) {
                      changed |= callback(call.method).add(j);
                      changed |= callbackValues(call.method, j).addAll(callbackValues(target, i));
                    }
                }
              }
          if (participants.contains(target) && call.method != null)
            changed |= participants.add(call.method);
        }
      }
      if (!changed) break;
    }
    if (changed && !exhausted)
      diagnostics.add(
          Findings.diagnostic(
              "GATEWAY_FLOW_BOUND",
              "",
              "Source propagation reached its bounded iteration limit; unresolved paths remain"
                  + " unknown."));
  }

  private Origin value(Node node, int depth, Set<Node> seen) {
    if (node == null || depth > 24 || !tick() || !seen.add(node)) return null;
    try {
      Origin direct = sources.get(node);
      if (direct != null) return direct;
      if (node.kind.equals("PAREN") || node.kind.equals("CAST"))
        return node.args.isEmpty() ? null : value(node.args.get(0), depth + 1, seen);
      if (node.kind.equals("NAME") || node.kind.equals("FIELD") && node.receiver != null)
        return nameValue(node, depth, seen);
      if (node.kind.equals("BINARY") && node.name.equals("+")) {
        Origin found = null;
        for (Node child : node.args) found = merge(found, value(child, depth + 1, seen), false);
        return found;
      }
      if (node.kind.equals("CONDITIONAL") && node.args.size() == 3) {
        Origin left = value(node.args.get(1), depth + 1, seen),
            right = value(node.args.get(2), depth + 1, seen);
        return merge(left, right, left == null || right == null);
      }
      if (!node.kind.equals("CALL")) return null;
      JavaGraph.Edge edge = graph.resolve(node);
      Origin result = null;
      boolean missing = false;
      for (Method target : edge.targets) {
        Origin summary = returns.get(target);
        if (summary == null) {
          missing = true;
          continue;
        }
        Origin substituted = null;
        boolean needsInput = false;
        for (int i = 0; i < target.params.size(); i++)
          if (summary.dependencies.contains(target.params.get(i).node)) {
            needsInput = true;
            if (i < node.args.size())
              substituted = merge(substituted, value(node.args.get(i), depth + 1, seen), false);
          }
        if (needsInput && substituted == null) {
          missing = true;
          continue;
        }
        if (needsInput) {
          Origin without = new Origin(summary.candidate, summary.evidence, identity());
          summary = merge(without, substituted, true);
        }
        result = merge(result, summary, false);
      }
      if (result != null)
        return merge(
            result,
            at(node, "A bounded source-local return carries model-derived data."),
            missing || edge.candidate);
      if ((node.name.equals("readTree") || node.name.equals("valueToTree"))
          && node.args.size() == 1
          && typed(node.receiver, "com.fasterxml.jackson.databind.ObjectMapper"))
        return value(node.args.get(0), depth + 1, seen);
      if (preserved(node)) return value(node.receiver, depth + 1, seen);
      return null;
    } finally {
      seen.remove(node);
    }
  }

  private boolean preserved(Node call) {
    if (call.receiver == null) return false;
    String name = call.name;
    if (name.equals("toString") && envelope(call.receiver, 0)) return false;
    if (name.equals("get") || name.equals("path")) {
      if (call.args.size() != 1) return false;
      Node key = call.args.get(0);
      return !key.kind.equals("LITERAL") || !METADATA.contains(key.literalValue);
    }
    return call.args.isEmpty()
        && Arrays.asList(
                "body",
                "string",
                "asText",
                "textValue",
                "asInt",
                "asLong",
                "asDouble",
                "asBoolean",
                "toString",
                "trim",
                "strip",
                "choices",
                "message",
                "content",
                "delta")
            .contains(name);
  }

  private Origin nameValue(Node use, int depth, Set<Node> seen) {
    Node declaration = graph.declaration(use);
    if (declaration == null) return null;
    List<Node> changes = assignments(declaration, use);
    if (!changes.isEmpty()) {
      Node last = changes.get(changes.size() - 1);
      if (!last.name.equals("=")) return null;
      if (scope(last) == scope(use)) return value(last.initializer, depth + 1, seen);
      if (changes.size() == 1 && tryAssigned(last, use))
        return candidate(value(last.initializer, depth + 1, seen));
      return null;
    }
    if (declaration.kind.equals("PARAM")) return parameters.get(declaration);
    if (declaration.kind.equals("FIELD") && eventOwners.contains(declaration.ownerType))
      return eventField(declaration, depth, seen);
    if (!declaration.kind.equals("VAR")) return null;
    if (declaration.collection != null)
      return candidate(value(declaration.collection, depth + 1, seen));
    Origin initial = value(declaration.initializer, depth + 1, seen);
    if (initial != null) return initial;
    // A source-local collection assembled from model elements is a candidate summary only.
    List<Node> local = methodCalls.get(declaration.method);
    Origin collected = null;
    if (local != null && (collectionType(declaration) || mapType(declaration)))
      for (Node call : local) {
        if (!tick()) break;
        if (call.start <= declaration.start || call.start >= use.start) continue;
        if (call.name.equals("add")
            && call.args.size() == 1
            && graph.declaration(call.receiver) == declaration)
          collected = merge(collected, value(call.args.get(0), depth + 1, seen), true);
        if (call.name.equals("put")
            && call.args.size() == 2
            && graph.declaration(call.receiver) == declaration)
          collected = merge(collected, value(call.args.get(1), depth + 1, seen), true);
        if (call.name.equals("forEach") && call.args.size() == 1) {
          Node reference = call.args.get(0);
          if (reference.kind.equals("METHOD_REF")
              && reference.name.equals("add")
              && graph.declaration(reference.receiver) == declaration
              && (typed(call.receiver, "com.fasterxml.jackson.databind.JsonNode")
                  || typed(call.receiver, "java.util.List")
                  || typed(call.receiver, "java.util.Collection")))
            collected = merge(collected, value(call.receiver, depth + 1, seen), true);
        }
      }
    return collected;
  }

  private boolean collectionType(Node declaration) {
    return Arrays.asList(
            "java.util.List",
            "java.util.ArrayList",
            "java.util.Collection",
            "java.util.Set",
            "java.util.HashSet",
            "java.util.LinkedHashSet")
        .contains(graph.declaredType(declaration));
  }

  private boolean mapType(Node declaration) {
    return Arrays.asList("java.util.Map", "java.util.HashMap", "java.util.LinkedHashMap")
        .contains(graph.declaredType(declaration));
  }

  private Origin eventField(Node field, int depth, Set<Node> seen) {
    Origin collected = null;
    String type = graph.declaredType(field);
    boolean builder =
        type.equals("java.lang.StringBuilder") || type.equals("java.lang.StringBuffer");
    for (Method method : field.ownerType.methods) {
      List<Node> local = methodCalls.get(method);
      if (local == null) continue;
      for (Node call : local) {
        if (!tick()) return null;
        if (graph.declaration(call.receiver) != field) continue;
        int argument =
            builder && call.name.equals("append") && call.args.size() == 1
                ? 0
                : collectionType(field) && call.name.equals("add") && call.args.size() == 1
                    ? 0
                    : mapType(field) && call.name.equals("put") && call.args.size() == 2 ? 1 : -1;
        if (argument >= 0)
          collected = merge(collected, value(call.args.get(argument), depth + 1, seen), true);
      }
    }
    return collected;
  }

  private List<Node> assignments(Node declaration, Node use) {
    List<Node> result = new ArrayList<Node>();
    List<Node> all = writes.get(declaration.method);
    if (all != null)
      for (Node assignment : all) {
        if (!tick()) break;
        if (assignment.start > declaration.start
            && assignment.start < use.start
            && graph.declaration(assignment.receiver) == declaration) result.add(assignment);
      }
    Collections.sort(
        result,
        new Comparator<Node>() {
          public int compare(Node a, Node b) {
            return a.start < b.start ? -1 : a.start == b.start ? 0 : 1;
          }
        });
    return result;
  }

  private Node scope(Node node) {
    for (Node p = node.parent; p != null; p = p.parent)
      if (Arrays.asList(
              "BLOCK", "IF", "FOR", "LOOP", "TRY", "CATCH", "FINALLY", "SWITCH", "CASE", "LAMBDA")
          .contains(p.kind)) return p;
    return null;
  }

  private boolean tryAssigned(Node assignment, Node use) {
    Node statement = assignment.parent;
    if (statement == null
        || !statement.kind.equals("EXPR_STMT")
        || statement.parent == null
        || !statement.parent.kind.equals("BLOCK")) return false;
    Node block = statement.parent, guarded = block.parent;
    if (guarded == null
        || !guarded.kind.equals("TRY")
        || scope(guarded) == null
        || !scope(guarded).kind.equals("BLOCK")
        || !JavaSyntax.contains(scope(guarded), use)
        || guarded.end > use.start) return false;
    boolean catcher = false;
    for (Node child : guarded.children) {
      if (child.kind.equals("FINALLY")) return false;
      if (child.kind.equals("CATCH")) {
        catcher = true;
        Node body = null;
        for (Node c : child.children) if (c.kind.equals("BLOCK")) body = c;
        if (!terminates(body)) return false;
      }
    }
    return catcher;
  }

  private boolean terminates(Node block) {
    if (block == null || block.children.isEmpty()) return false;
    Node last = block.children.get(block.children.size() - 1);
    return last.kind.equals("RETURN") || last.kind.equals("THROW");
  }

  private Node unfold(Node node, int depth) {
    if (node == null || depth > 12 || !tick()) return node;
    if ((node.kind.equals("PAREN") || node.kind.equals("CAST")) && !node.args.isEmpty())
      return unfold(node.args.get(0), depth + 1);
    if (node.kind.equals("NAME")) {
      Node declaration = graph.declaration(node);
      if (declaration != null && declaration.kind.equals("VAR")) {
        List<Node> assignments = assignments(declaration, node);
        if (!assignments.isEmpty()) {
          Node last = assignments.get(assignments.size() - 1);
          return last.name.equals("=")
                  && (scope(last) == scope(node)
                      || assignments.size() == 1 && tryAssigned(last, node))
              ? unfold(last.initializer, depth + 1)
              : node;
        }
        if (declaration.initializer != null) return unfold(declaration.initializer, depth + 1);
      }
    }
    return node;
  }

  private boolean envelope(Node node, int depth) {
    if (node == null || depth > 12 || !tick()) return false;
    String type = graph.declaredType(node);
    if (type.equals("okhttp3.Response")
        || type.equals("okhttp3.ResponseBody")
        || type.equals("java.net.http.HttpResponse")) return true;
    if (envelopes.contains(node)) return true;
    Node expanded = unfold(node, 0);
    return expanded != node && envelope(expanded, depth + 1);
  }
}
