import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { parse } from "@babel/parser";

const root = process.argv[2];
if (!root) {
  console.error("Usage: node ast_project_analyzer.mjs <project>");
  process.exit(2);
}

const extensions = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]);
const files = [];
function collect(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if ([".git", "node_modules", "dist", "build", "target", "__pycache__"].includes(entry.name)) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) collect(full);
    else if (extensions.has(path.extname(entry.name).toLowerCase()) && fs.statSync(full).size <= 2_000_000) files.push(full);
  }
}
collect(root);

const modules = new Map();
const rules = {
  "js-command-injection": ["User-controlled data reaches command execution", "HIGH", "CWE-78", "Avoid shell execution; use a non-shell API with strict argument allowlists."],
  "js-xss": ["User-controlled data reaches an HTML injection sink", "HIGH", "CWE-79", "Use textContent or a context-aware sanitizer instead of assigning untrusted HTML."],
  "js-code-injection": ["User-controlled data reaches dynamic code execution", "CRITICAL", "CWE-95", "Remove dynamic evaluation and replace it with a fixed parser or allowlisted operation."],
  "js-path-traversal": ["User-controlled data reaches a filesystem path", "HIGH", "CWE-22", "Resolve against a fixed base directory and enforce that the normalized path stays below it."],
  "js-sql-injection": ["User-controlled data reaches a SQL query", "HIGH", "CWE-89", "Use parameterized queries and pass user input as bound values, not query text."],
};

function parseFile(file) {
  const source = fs.readFileSync(file, "utf8");
  return { file, source, ast: parse(source, {
    sourceType: "unambiguous",
    plugins: ["typescript", "jsx", "decorators-legacy", "classProperties"],
  }) };
}

for (const file of files) modules.set(file, parseFile(file));

function lineOf(node) { return node.loc?.start?.line ?? 1; }
function text(mod, node) { return mod.source.slice(node.start, node.end).replace(/\s+/g, " ").trim(); }
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
function visit(node, callback) {
  if (!node || typeof node !== "object") return;
  callback(node);
  for (const [key, value] of Object.entries(node)) {
    if (["loc", "start", "end"].includes(key)) continue;
    if (Array.isArray(value)) value.forEach((child) => visit(child, callback));
    else if (value && typeof value === "object") visit(value, callback);
  }
}
function functionDefinitions(mod) {
  const result = new Map();
  visit(mod.ast, (node) => {
    if (node.type === "FunctionDeclaration" && node.id?.name) result.set(node.id.name, node);
    if (node.type === "VariableDeclarator" && node.id?.type === "Identifier" &&
        ["FunctionExpression", "ArrowFunctionExpression"].includes(node.init?.type)) {
      result.set(node.id.name, node.init);
    }
  });
  return result;
}
function imports(mod) {
  const result = new Map();
  visit(mod.ast, (node) => {
    if (node.type !== "ImportDeclaration") return;
    const target = path.resolve(path.dirname(mod.file), node.source.value);
    const candidates = [target, `${target}.js`, `${target}.ts`, `${target}.jsx`, `${target}.tsx`, path.join(target, "index.js")];
    const resolved = candidates.find((candidate) => modules.has(candidate));
    if (!resolved) return;
    for (const specifier of node.specifiers) {
      if (specifier.type === "ImportSpecifier") {
        result.set(specifier.local.name, { file: resolved, exported: specifier.imported.name });
      } else if (specifier.type === "ImportDefaultSpecifier") {
        result.set(specifier.local.name, { file: resolved, exported: "default" });
      }
    }
  });
  return result;
}
function requestSource(node) {
  return node?.type === "MemberExpression" &&
    !node.computed &&
    node.object?.type === "MemberExpression" &&
    node.object.object?.name === "req" &&
    ["query", "body", "params", "headers", "cookies"].includes(node.object.property?.name);
}
function sinkRule(name) {
  if (["child_process.exec", "child_process.execSync", "exec", "execSync", "execFile"].includes(name)) return "js-command-injection";
  if (["eval", "Function"].includes(name)) return "js-code-injection";
  if (["fs.readFile", "fs.readFileSync", "fs.writeFile", "fs.writeFileSync", "fs.unlink", "fs.unlinkSync", "path.join", "path.resolve"].includes(name)) return "js-path-traversal";
  if (["db.query", "connection.query", "pool.query", "sequelize.query"].includes(name)) return "js-sql-injection";
  return null;
}

const findings = [];
const seen = new Set();
function add(ruleId, mod, node, evidence) {
  const key = `${ruleId}:${mod.file}:${lineOf(node)}`;
  if (seen.has(key)) return;
  seen.add(key);
  const rule = rules[ruleId];
  findings.push({
    rule_id: ruleId, title: rule[0], severity: rule[1], confidence: "high",
    cwe: rule[2], cvss: "context-dependent", file: mod.file, line: lineOf(node),
    evidence: `${evidence} -> ${text(mod, node)}`, remediation: rule[3],
  });
}

function analyzeImportedFunction(mod, call, imported) {
  const target = modules.get(imported.file);
  const definition = target && functionDefinitions(target).get(imported.exported);
  if (!definition || !call.arguments.some(requestSource)) return;
  const tainted = new Set(definition.params.filter((parameter, index) =>
    parameter.type === "Identifier" && requestSource(call.arguments[index])).map((parameter) => parameter.name));
  if (!tainted.size) return;
  visit(definition.body, (node) => {
    if (node.type !== "CallExpression") return;
    const rule = sinkRule(calleeName(node.callee));
    const argument = node.arguments[0];
    if (rule && argument?.type === "Identifier" && tainted.has(argument.name)) {
      add(rule, target, node, `request input -> imported ${imported.exported}() -> ${calleeName(node.callee)}`);
    }
    if (node.type === "AssignmentExpression" && node.left?.property?.name === "innerHTML" &&
        argument?.type === "Identifier" && tainted.has(argument.name)) {
      add("js-xss", target, node, `request input -> imported ${imported.exported}() -> innerHTML`);
    }
  });
}

for (const mod of modules.values()) {
  const imported = imports(mod);
  visit(mod.ast, (node) => {
    if (node.type !== "CallExpression" || node.callee?.type !== "Identifier") return;
    const binding = imported.get(node.callee.name);
    if (binding) analyzeImportedFunction(mod, node, binding);
  });
}
process.stdout.write(JSON.stringify(findings));
