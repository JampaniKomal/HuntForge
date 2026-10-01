// Parse every rule's KQL with Kibana's own grammar and evaluate it on the test events.
//
//   python scripts/kql_cases.py > cases.json
//   node scripts/kql_check.mjs grammar.peggy cases.json
//
// grammar.peggy is Kibana's KQL grammar (kbn-es-query); CI downloads it at a
// pinned commit rather than vendoring it. Parsing with it proves the quoting,
// escaping and keyword handling read the way Kibana reads them. The evaluator
// below then applies the parsed query to each event with the semantics the
// rules are written for: case-insensitive values (a lowercase-normalised
// keyword field), `*` wildcards, `field: *` as "the field exists", and any
// element of a list matching. Every rule must select exactly the events the
// HuntForge matcher selects.

import { readFileSync } from "node:fs";
import peggy from "peggy";

const [grammarPath, casesPath] = process.argv.slice(2);
const WILDCARD = "@kuery-wildcard@";

const nodeTypes = {
  function: {
    buildNode: (name, ...args) => ({ type: "function", function: name, arguments: args.map((v) => ({ type: "literal", value: v })) }),
    buildNodeWithArgumentNodes: (name, args) => ({ type: "function", function: name, arguments: args }),
  },
  literal: { buildNode: (value, isQuoted = false) => ({ type: "literal", value, isQuoted }) },
  wildcard: {
    KQL_WILDCARD_SYMBOL: WILDCARD,
    buildNode: (value) => ({ type: "wildcard", value }),
    isNode: (node) => node?.type === "wildcard",
    hasLeadingWildcard: (node) => node.value.startsWith(WILDCARD),
  },
};

const parser = peggy.generate(readFileSync(grammarPath, "utf8"));
const parse = (kql) => parser.parse(kql, { helpers: { nodeTypes }, allowLeadingWildcards: true });

function getField(event, path) {
  let current = event;
  for (const part of path.split(".")) {
    if (current === null || typeof current !== "object" || !(part in current)) return undefined;
    current = current[part];
  }
  return current;
}

const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function matchesValue(actual, node) {
  if (actual === undefined || actual === null) return false;
  if (Array.isArray(actual)) return actual.some((item) => matchesValue(item, node));
  const text = String(actual).toLowerCase();
  if (node.type === "wildcard") {
    const regex = new RegExp("^" + node.value.split(WILDCARD).map((p) => escapeRegex(p.toLowerCase())).join(".*") + "$", "s");
    return regex.test(text);
  }
  if (typeof node.value === "boolean" || typeof node.value === "number") return text === String(node.value);
  if (!node.isQuoted && node.value !== "" && !Number.isNaN(Number(node.value)) && !Number.isNaN(Number(actual))) {
    return Number(node.value) === Number(actual);
  }
  return text === String(node.value).toLowerCase();
}

function evaluate(node, event) {
  if (node.type !== "function") throw new Error(`unexpected node ${JSON.stringify(node)}`);
  const args = node.arguments;
  switch (node.function) {
    case "and":
      return args.every((n) => evaluate(n, event));
    case "or":
      return args.some((n) => evaluate(n, event));
    case "not":
      return !evaluate(args[0], event);
    case "is": {
      const [field, value] = args;
      if (field.type !== "literal" || field.value === null) throw new Error("query has a value with no field");
      const actual = getField(event, String(field.value));
      if (value.type === "wildcard" && value.value === WILDCARD) return actual !== undefined && actual !== null;
      return matchesValue(actual, value);
    }
    default:
      throw new Error(`unsupported KQL function ${node.function}`);
  }
}

const cases = JSON.parse(readFileSync(casesPath, "utf8"));
let failures = 0;
for (const rule of cases.rules) {
  let ast;
  try {
    ast = parse(rule.kql);
  } catch (err) {
    failures++;
    console.log(`FAIL ${rule.name}: Kibana cannot parse it: ${err.message}\n  ${rule.kql}`);
    continue;
  }
  const got = cases.events.flatMap((e, i) => (evaluate(ast, e.event) ? [i] : []));
  const want = new Set(rule.expected);
  const extra = got.filter((i) => !want.has(i)).map((i) => cases.events[i].name);
  const missing = rule.expected.filter((i) => !got.includes(i)).map((i) => cases.events[i].name);
  if (extra.length || missing.length) {
    failures++;
    console.log(`FAIL ${rule.name}\n  only the matcher: ${missing.join("; ")}\n  only KQL: ${extra.join("; ")}\n  ${rule.kql}`);
  } else {
    console.log(`ok   ${rule.name}: ${got.length} of ${cases.events.length} events`);
  }
}
console.log(failures ? `\n${failures} rule(s) differ` : `\nall ${cases.rules.length} rules agree with the matcher`);
process.exit(failures ? 1 : 0);
