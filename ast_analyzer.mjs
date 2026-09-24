import fs from "node:fs";
import process from "node:process";
import { parse } from "@babel/parser";

const file = process.argv[2];
if (!file) {
  console.error("Usage: node ast_analyzer.mjs <file>");
  process.exit(2);
}

const source = fs.readFileSync(file, "utf8");
let ast;
try {
  ast = parse(source, {
    sourceType: "unambiguous",
    errorRecovery: false,
    plugins: ["typescript", "jsx", "decorators-legacy", "classProperties"],
  });
} catch (error) {
  console.error(`${error.name}: ${error.message}`);
  process.exit(1);
}

const findings = [];
const tainted = new Map();
const seen = new Set();
const functions = new Map();
const analyzedCalls = new Set();

const rules = {
  "js-command-injection": {
    title: "User-controlled data reaches command execution",
    severity: "HIGH",
    cwe: "CWE-78",
    remediation: "Avoid shell execution; use a non-shell API with strict argument allowlists.",
  },
  "js-xss": {
    title: "User-controlled data reaches an HTML injection sink",
    severity: "HIGH",
    cwe: "CWE-79",
    remediation: "Use textContent or a context-aware sanitizer instead of assigning untrusted HTML.",
  },
  "js-code-injection": {
    title: "User-controlled data reaches dynamic code execution",
    severity: "CRITICAL",
    cwe: "CWE-95",
    remediation: "Remove dynamic evaluation and replace it with a fixed parser or allowlisted operation.",
  },
  "js-path-traversal": {
    title: "User-controlled data reaches a filesystem path",
    severity: "HIGH",
    cwe: "CWE-22",
    remediation: "Resolve against a fixed base directory and enforce that the normalized path stays below it.",
  },
  "js-sql-injection": {
    title: "User-controlled data reaches a SQL query",
    severity: "HIGH",
    cwe: "CWE-89",
    remediation: "Use parameterized queries and pass user input as bound values, not query text.",
  },
};

function lineOf(node) {
  return node.loc?.start?.line ?? 1;
}

function text(node) {
  return source.slice(node.start, node.end).replace(/\s+/g, " ").trim();
}

function add(ruleId, node, pathText) {
  const key = `${ruleId}:${lineOf(node)}:${pathText}`;
  if (seen.has(key)) return;
  seen.add(key);
  const rule = rules[ruleId];
  findings.push({
    rule_id: ruleId,
    title: rule.title,
    severity: rule.severity,
    confidence: "high",
    cwe: rule.cwe,
    cvss: "context-dependent",
    line: lineOf(node),
    evidence: `${pathText} -> ${text(node)}`,
    remediation: rule.remediation,
  });
}

function isRequestSource(node) {
  if (!node) return false;
  if (node.type === "MemberExpression" && !node.computed &&
      node.object?.type === "MemberExpression" &&
      node.object.object?.name === "req") {
    return ["query", "body", "params", "headers", "cookies"].includes(node.object.property?.name);
  }
  if (node.type === "MemberExpression" && node.object?.name === "location") return true;
  return false;
}

function isTainted(node, visited = new Set()) {
  if (!node) return false;
  if (isRequestSource(node)) return true;
  if (node.type === "StringLiteral" || node.type === "NumericLiteral" ||
      node.type === "BooleanLiteral" || node.type === "NullLiteral") return false;
  if (node.type === "Identifier") {
    if (visited.has(node.name)) return false;
    visited.add(node.name);
    return tainted.has(node.name);
  }
  if (node.type === "TemplateLiteral") return node.expressions.some((item) => isTainted(item, visited));
  if (node.type === "BinaryExpression" || node.type === "LogicalExpression") {
    return isTainted(node.left, visited) || isTainted(node.right, visited);
  }
  if (node.type === "ConditionalExpression") {
    return isTainted(node.consequent, visited) || isTainted(node.alternate, visited);
  }
  if (node.type === "CallExpression" || node.type === "NewExpression") {
    if (node.type === "CallExpression" && isXssSanitizer(node)) return false;
    return node.arguments.some((item) => item.type !== "SpreadElement" && isTainted(item, visited));
  }
  if (node.type === "MemberExpression") return isTainted(node.object, visited);
  return false;
}

function assignmentTargetName(node) {
  return node?.type === "Identifier" ? node.name : null;
}

function calleeName(node) {
  if (!node) return "";
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") {
    const left = calleeName(node.object);
    const right = node.property?.name ?? "";
    return left ? `${left}.${right}` : right;
  }
  return "";
}

function isXssSanitizer(node) {
  const name = calleeName(node?.callee);
  return ["DOMPurify.sanitize", "sanitizeHtml", "escapeHtml", "encodeHtml"].includes(name);
}

function collectFunctions(node) {
  if (!node || typeof node !== "object") return;
  if (node.type === "FunctionDeclaration" && node.id?.name) {
    functions.set(node.id.name, node);
  }
  if (node.type === "VariableDeclarator" && node.id?.type === "Identifier" &&
      (node.init?.type === "FunctionExpression" || node.init?.type === "ArrowFunctionExpression")) {
    functions.set(node.id.name, node.init);
  }
  for (const [key, value] of Object.entries(node)) {
    if (key === "loc" || key === "start" || key === "end") continue;
    if (value && typeof value === "object") {
      if (Array.isArray(value)) value.forEach(collectFunctions);
      else collectFunctions(value);
    }
  }
}

function analyzeFunctionCall(name, node) {
  const definition = functions.get(name);
  if (!definition || analyzedCalls.has(node.start)) return;
  const taintedArguments = definition.params
    .map((parameter, index) => ({
      name: parameter.type === "Identifier" ? parameter.name : null,
      tainted: isTainted(node.arguments[index]),
    }))
    .filter((parameter) => parameter.name && parameter.tainted);
  if (taintedArguments.length === 0) return;
  analyzedCalls.add(node.start);
  const previous = new Map(tainted);
  for (const parameter of taintedArguments) tainted.set(parameter.name, "interprocedural request input");
  walk(definition.body);
  tainted.clear();
  previous.forEach((value, key) => tainted.set(key, value));
}

function walk(node, parent = null) {
  if (!node || typeof node !== "object") return;

  if (node.type === "VariableDeclarator") {
    const name = assignmentTargetName(node.id);
    if (name && isTainted(node.init)) tainted.set(name, text(node.init));
  }
  if (node.type === "AssignmentExpression") {
    const name = assignmentTargetName(node.left);
    if (name && isTainted(node.right)) tainted.set(name, text(node.right));
    if (node.left.type === "MemberExpression" && node.left.property?.name === "innerHTML" &&
        isTainted(node.right)) {
      add("js-xss", node, "request input -> innerHTML");
    }
  }
  if (node.type === "CallExpression") {
    const name = calleeName(node.callee);
    const argument = node.arguments[0];
    if (node.callee.type === "Identifier") {
      analyzeFunctionCall(name, node);
    }
    if (["eval", "Function"].includes(name) && isTainted(argument)) {
      add("js-code-injection", node, "request input -> eval");
    }
    if (["child_process.exec", "child_process.execSync", "exec", "execSync", "execFile"].includes(name) &&
        isTainted(argument)) {
      add("js-command-injection", node, "request input -> command execution");
    }
    if (["fs.readFile", "fs.readFileSync", "fs.writeFile", "fs.writeFileSync",
      "fs.unlink", "fs.unlinkSync", "path.join", "path.resolve"].includes(name) &&
        isTainted(argument)) {
      add("js-path-traversal", node, "request input -> filesystem path");
    }
    if (["db.query", "connection.query", "pool.query", "sequelize.query"].includes(name) &&
        isTainted(argument)) {
      add("js-sql-injection", node, "request input -> SQL query");
    }
    if (isXssSanitizer(node) && isTainted(argument)) {
      return;
    }
  }

  for (const [key, value] of Object.entries(node)) {
    if (key === "loc" || key === "start" || key === "end") continue;
    if (value && typeof value === "object") {
      if (Array.isArray(value)) value.forEach((child) => walk(child, node));
      else walk(value, node);
    }
  }
}

collectFunctions(ast);
walk(ast);
process.stdout.write(JSON.stringify(findings));
