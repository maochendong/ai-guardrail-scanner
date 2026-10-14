package dev.aiguard.compat;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.*;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/** Strict trees only: bounded nesting and no duplicate member ambiguity. */
public final class Json {
  public static final Gson COMPACT = new GsonBuilder().disableHtmlEscaping().create();
  public static final Gson PRETTY =
      new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

  private Json() {}

  public static JsonElement parse(String text) throws IOException {
    JsonReader reader = new JsonReader(new StringReader(text));
    reader.setStrictness(Strictness.STRICT);
    int[] nodes = {0};
    JsonElement value = value(reader, 0, nodes);
    if (reader.peek() != JsonToken.END_DOCUMENT) throw new IOException("INVALID_JSON");
    return value;
  }

  private static JsonElement value(JsonReader reader, int depth, int[] nodes) throws IOException {
    if (depth > 64 || ++nodes[0] > 100000) throw new IOException("JSON_LIMIT");
    JsonToken token = reader.peek();
    if (token == JsonToken.BEGIN_OBJECT) {
      reader.beginObject();
      JsonObject out = new JsonObject();
      Set<String> keys = new HashSet<String>();
      while (reader.hasNext()) {
        String key = reader.nextName();
        if (!keys.add(key)) throw new IOException("DUPLICATE_JSON_KEY");
        out.add(key, value(reader, depth + 1, nodes));
      }
      reader.endObject();
      return out;
    }
    if (token == JsonToken.BEGIN_ARRAY) {
      reader.beginArray();
      JsonArray out = new JsonArray();
      while (reader.hasNext()) out.add(value(reader, depth + 1, nodes));
      reader.endArray();
      return out;
    }
    if (token == JsonToken.STRING) return new JsonPrimitive(reader.nextString());
    if (token == JsonToken.BOOLEAN) return new JsonPrimitive(reader.nextBoolean());
    if (token == JsonToken.NULL) {
      reader.nextNull();
      return JsonNull.INSTANCE;
    }
    if (token == JsonToken.NUMBER) {
      String number = reader.nextString();
      if (number.length() > 128) throw new IOException("JSON_NUMBER_LIMIT");
      try {
        return new JsonPrimitive(new BigDecimal(number));
      } catch (NumberFormatException error) {
        throw new IOException("INVALID_JSON_NUMBER");
      }
    }
    throw new IOException("INVALID_JSON");
  }

  public static String readResource(String name) throws IOException {
    InputStream stream = Json.class.getResourceAsStream(name);
    if (stream == null) throw new IOException("MISSING_RESOURCE");
    try (InputStream input = stream;
        ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      byte[] buffer = new byte[8192];
      int count;
      while ((count = input.read(buffer)) >= 0) {
        if (output.size() + count > 1024 * 1024) throw new IOException("RESOURCE_LIMIT");
        output.write(buffer, 0, count);
      }
      return new String(output.toByteArray(), StandardCharsets.UTF_8);
    }
  }
}
