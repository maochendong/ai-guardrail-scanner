package dev.aiguard.compat;

import dev.aiguard.compat.pygrammar.Python3Lexer;
import dev.aiguard.compat.pygrammar.Python3Parser;
import java.util.IdentityHashMap;
import java.util.Map;
import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;
import org.antlr.v4.runtime.Token;

/** Shared bounded syntax only; consumers must treat returned parse trees as read-only. */
public final class PythonSyntax {
  private PythonSyntax() {}

  public static final class Unit {
    public final ParserRuleContext tree;
    public final boolean fstrings;
    /** Empty on success; SYNTAX, LIMIT or DEPTH on a discarded parse. */
    public final String failureReason;

    private Unit(ParserRuleContext tree, boolean fstrings, String failureReason) {
      this.tree = tree;
      this.fstrings = fstrings;
      this.failureReason = failureReason;
    }
  }

  /** Owned by one scan; analysis state and analysis budgets must never be stored here. */
  public static final class Cache {
    private final Map<SourceFile, Unit> units = new IdentityHashMap<SourceFile, Unit>();

    public Unit parse(SourceFile file, Cancel cancel) {
      cancel.check();
      Unit unit = units.get(file);
      if (unit == null) {
        unit = PythonSyntax.parse(file, cancel);
        units.put(file, unit);
      }
      return unit;
    }
  }

  private static final class Limit extends RuntimeException {
    private static final long serialVersionUID = 1L;
  }

  public static Unit parse(SourceFile file, final Cancel cancel) {
    cancel.check();
    final boolean[] failed = {false};
    boolean fstrings = false;
    BaseErrorListener listener =
        new BaseErrorListener() {
          @Override
          public void syntaxError(
              Recognizer<?, ?> recognizer,
              Object offending,
              int line,
              int column,
              String message,
              RecognitionException error) {
            failed[0] = true;
          }
        };
    try {
      Python3Lexer lexer =
          new Python3Lexer(CharStreams.fromString(file.content)) {
            private int count;

            @Override
            public Token nextToken() {
              if ((++count & 255) == 0) cancel.check();
              if (count > 150000) throw new Limit();
              return super.nextToken();
            }
          };
      lexer.removeErrorListeners();
      lexer.addErrorListener(listener);
      CommonTokenStream tokens =
          new CommonTokenStream(lexer) {
            private int reads;

            @Override
            public Token LT(int lookahead) {
              if ((++reads & 1023) == 0) cancel.check();
              if (reads > 5000000) throw new Limit();
              return super.LT(lookahead);
            }
          };
      tokens.fill();
      for (Token token : tokens.getTokens())
        if (token.getType() == Python3Lexer.STRING) {
          String value = token.getText();
          int quote =
              Math.min(
                  value.indexOf('\'') < 0 ? 10 : value.indexOf('\''),
                  value.indexOf('"') < 0 ? 10 : value.indexOf('"'));
          if (quote < 4
              && value.substring(0, quote).toLowerCase(java.util.Locale.ROOT).indexOf('f') >= 0)
            fstrings = true;
        }
      Python3Parser parser = new Python3Parser(tokens);
      parser.removeErrorListeners();
      parser.addErrorListener(listener);
      ParserRuleContext tree = parser.file_input();
      return failed[0] ? new Unit(null, fstrings, "SYNTAX") : new Unit(tree, fstrings, "");
    } catch (Limit limit) {
      return new Unit(null, fstrings, "LIMIT");
    } catch (StackOverflowError error) {
      return new Unit(null, fstrings, "DEPTH");
    }
  }
}
