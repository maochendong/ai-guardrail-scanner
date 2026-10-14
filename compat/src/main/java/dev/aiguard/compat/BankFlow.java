package dev.aiguard.compat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Bounded, language-neutral local flow. Unknown constructs never establish controls. */
public final class BankFlow {
  private BankFlow() {}

  public static final class Program {
    public final List<Function> functions = new ArrayList<Function>();
    public final List<Map<String, Object>> diagnostics = new ArrayList<Map<String, Object>>();
  }

  public static final class Function {
    public String path = "", symbol = "";
    public int line = 1;
    public final List<String> params = new ArrayList<String>();
    public final List<String> parameterNames = new ArrayList<String>();
    public final List<Stmt> body = new ArrayList<Stmt>();
  }

  public static final class Expr {
    /** NAME, CALL, NEW, MEMBER, MAP, LITERAL, UNARY, BINARY, COMPOSITE or UNKNOWN. */
    public String kind, name = "", symbol = "", operator = "", path = "";

    public Object literal;
    public Expr receiver;
    public boolean bindingUncertain;
    public int line = 1;
    public final List<Expr> args = new ArrayList<Expr>();
    public final List<String> argNames = new ArrayList<String>();
    public final java.util.Map<String, Expr> members = new java.util.LinkedHashMap<String, Expr>();

    public Expr(String kind) {
      this.kind = kind;
    }
  }

  public static final class Stmt {
    /** ASSIGN, EXPR, IF, RETURN, YIELD, THROW, TRY, or UNKNOWN. */
    public String kind, target = "", path = "";

    public int line = 1;
    public Expr expr;
    public final List<Stmt> body = new ArrayList<Stmt>();
    public final List<Stmt> otherwise = new ArrayList<Stmt>();
    public final List<List<Stmt>> handlers = new ArrayList<List<Stmt>>();
    public final List<Stmt> finalizer = new ArrayList<Stmt>();

    public Stmt(String kind) {
      this.kind = kind;
    }
  }
}
