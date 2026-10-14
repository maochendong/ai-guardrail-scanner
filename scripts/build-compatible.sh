#!/usr/bin/env bash
set -euo pipefail
task_root="$(cd "$(dirname "$0")/.." && pwd)"
task_java7_home="${JAVA7_HOME:-}"
if [[ -z "$task_java7_home" && -x /usr/libexec/java_home ]]; then
  task_java7_home="$(/usr/libexec/java_home -v 1.7 2>/dev/null || true)"
fi
if [[ ! -x "$task_java7_home/bin/javac" ]]; then
  echo 'Set JAVA7_HOME to a JDK 7 installation; the native Java 7 compiler prevents newer API leakage.' >&2
  exit 2
fi
task_javac_version="$("$task_java7_home/bin/javac" -version 2>&1)"
if [[ "$task_javac_version" != javac\ 1.7.* ]]; then
  echo 'JAVA7_HOME must point to an actual JDK 7 compiler, not only a compiler targeting Java 7.' >&2
  exit 2
fi
if [[ $# -eq 0 ]]; then set -- verify; fi
exec "$task_root/scripts/mvn.sh" -f "$task_root/compat/pom.xml" \
  -Dmaven.compiler.fork=true -Dmaven.compiler.executable="$task_java7_home/bin/javac" "$@"
