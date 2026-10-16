package dev.aiguard.compat;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Bounded, language-neutral local flow. Unknown constructs never establish controls. */
public final class BusinessFlow {
  private BusinessFlow() {}

  public static final class Program {
    public final List<Function> functions = new ArrayList<Function>();
    public final List<Map<String, Object>> diagnostics = new ArrayList<Map<String, Object>>();

    /** Files with discarded or unvisited source; local UNKNOWN nodes do not belong here. */
    public final Set<String> incompletePaths = new LinkedHashSet<String>();
  }

  public static final class Function {
    /** Unique source-definition identity; unlike symbol/arity, this separates overloads. */
    public String id = "";

    /** Async/decorated or otherwise unresolved execution cannot establish synchronous timing. */
    public boolean executionUncertain;

    public String path = "", symbol = "";
    public int line = 1;
    public final List<String> params = new ArrayList<String>();
    public final List<String> parameterNames = new ArrayList<String>();
    public final List<Stmt> body = new ArrayList<Stmt>();
  }

  public static final class Expr {
    /**
     * NAME, CALL, NEW, MEMBER, MAP, PUT_MEMBER, DICT_GET, JSON_LOADS, LITERAL, UNARY, BINARY,
     * COMPOSITE or UNKNOWN. MAP.name distinguishes dict/map/object; field updates carry
     * receiver/name and one argument, with operator=void for source setters.
     */
    public String kind, name = "", symbol = "", operator = "", path = "";

    public Object literal;
    public Expr receiver;
    public boolean bindingUncertain;

    /** A resolved source definition, never inferred by looking up symbol/arity. */
    public String localTargetId = "";

    public boolean localTargetCandidate;
    public int line = 1;
    public final List<Expr> args = new ArrayList<Expr>();
    public final List<String> argNames = new ArrayList<String>();
    public final java.util.Map<String, Expr> members = new java.util.LinkedHashMap<String, Expr>();

    public Expr(String kind) {
      this.kind = kind;
    }
  }

  public static final class Stmt {
    /** ASSIGN, EXPR, IF, RETURN, YIELD, THROW, TRY, ITERATE, or UNKNOWN. */
    public String kind, target = "", path = "";

    public int line = 1;
    public Expr expr;

    /** For UNKNOWN statements only: adapter-confirmed ordinary computations may set false. */
    public boolean orderUncertain = true;

    public final List<Stmt> body = new ArrayList<Stmt>();
    public final List<Stmt> otherwise = new ArrayList<Stmt>();
    public final List<List<Stmt>> handlers = new ArrayList<List<Stmt>>();
    public final List<Stmt> finalizer = new ArrayList<Stmt>();

    public Stmt(String kind) {
      this.kind = kind;
    }
  }
}
