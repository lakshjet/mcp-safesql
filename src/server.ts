// src/server.ts
// Minimal MCP server that safely exposes read-only SQL tools.
// - Only SELECT allowed
// - Only whitelisted VIEWS allowed
// - PII masking (email/phone/ssn) on results
// - Safe EXPLAIN that hides table/index names and literals

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { ToolHandlerContext } from "@modelcontextprotocol/sdk/server/types.js";
import { z } from "zod";

import sqlite3 from "sqlite3";
import { Client as PgClient } from "pg";
import { Parser } from "node-sql-parser";

// ---------------------- ENV / CONFIG ----------------------
const DB_TYPE = (process.env.DB_TYPE || "sqlite").toLowerCase();     // "sqlite" | "postgres"
const SQLITE_PATH = process.env.SQLITE_PATH || "./example.db";       // path to sqlite file
const PG_CONNECTION_STRING = process.env.PG_CONNECTION_STRING || ""; // postgres url
const SAFE_VIEWS = (process.env.SAFE_VIEWS || "safe_users_v")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean)
  .map(s => s.toLowerCase());                                        // normalized whitelist
const MAX_ROWS = Number(process.env.MAX_ROWS || 200);                 // cap rows

// ---------------------- DB HELPERS ------------------------
function openSqliteRO() {
  const mode = sqlite3.OPEN_READONLY;
  const db = new sqlite3.Database(SQLITE_PATH, mode);
  return db;
}

async function withPgClient<T>(fn: (c: PgClient) => Promise<T>): Promise<T> {
  const c = new PgClient({ connectionString: PG_CONNECTION_STRING });
  await c.connect();
  try { return await fn(c); }
  finally { await c.end(); }
}

// ---------------------- SQL SAFETY ------------------------
const parser = new Parser();
function dialectName(): "Postgresql" | "Sqlite" {
  return DB_TYPE === "postgres" ? "Postgresql" : "Sqlite";
}

function assertSelectOnly(sql: string) {
  const ast = parser.astify(sql, { database: dialectName() });
  if (Array.isArray(ast)) throw new Error("Only one statement allowed.");
  const t = (ast as any)?.type?.toLowerCase?.();
  if (t !== "select") throw new Error("Only SELECT queries are allowed.");
}

function tablesUsed(sql: string) {
  const list = parser.tableList(sql, { database: dialectName() }); // e.g. ["select::null::safe_users_v"]
  return list.map((s: string) => {
    const parts = s.split("::");                        // [type, schemaOrNull, table]
    const schema = parts[1] && parts[1] !== "null" ? parts[1] : null;
    const table = parts[2] || parts[1] || "";
    return (schema ? `${schema}.${table}` : table).toLowerCase();
  }).filter(Boolean);
}

function assertWhitelisted(sql: string) {
  const used = new Set(tablesUsed(sql));
  const allowed = new Set(SAFE_VIEWS);
  for (const name of used) {
    if (!allowed.has(name)) {
      throw new Error(`"${name}" is not whitelisted. Allowed views: ${Array.from(allowed).join(", ")}`);
    }
  }
}

function wrapWithLimit(sql: string, limit: number) {
  if (/limit\s+\d+/i.test(sql)) return sql; // user already set a LIMIT
  return `SELECT * FROM (${sql}) AS safe_sub LIMIT ${limit}`;
}

// ---------------------- PII MASKING -----------------------
function looksLikeEmail(v: string) { return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v); }
function looksLikePhone(v: string) { return /(\+?\d[\d\-\s().]{6,})/.test(v); }
function looksLikeSSN(v: string) { return /^\d{3}-\d{2}-\d{4}$/.test(v); }

function shouldMaskByColumn(col: string) {
  const c = col.toLowerCase();
  return c.includes("email") || c.includes("phone") || c.includes("mobile") ||
         (c.includes("contact") && c.includes("number")) ||
         c.includes("ssn") || (c.includes("social") && c.includes("security"));
}

function maskEmail(value: string) {
  const [u, d] = value.split("@");
  if (!d) return value.replace(/.(?=.{2})/g, "*");
  const uMasked = u.length <= 2 ? "*".repeat(u.length) : u[0] + "*".repeat(u.length - 2) + u[u.length - 1];
  const dMasked = d.replace(/(?<=.).(?=.*\.)/g, "*");
  return `${uMasked}@${dMasked}`;
}
function maskPhone(value: string) { return value.replace(/\d(?=\d{2}\b)/g, "*"); } // keep last 2 digits
function maskSSN(value: string) { return value.replace(/^\d{3}-\d{2}/, "***-**"); }

function maskValue(col: string, v: unknown) {
  if (v == null || typeof v !== "string") return v;
  if (shouldMaskByColumn(col) || looksLikeEmail(v) || looksLikePhone(v) || looksLikeSSN(v)) {
    if (looksLikeEmail(v)) return maskEmail(v);
    if (looksLikeSSN(v)) return maskSSN(v);
    if (looksLikePhone(v)) return maskPhone(v);
    return v.replace(/[A-Za-z0-9]/g, "*"); // generic fallback
  }
  return v;
}

function maskRows(rows: Array<Record<string, unknown>>) {
  return rows.map(r => {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(r)) out[k] = maskValue(k, v);
    return out;
  });
}

// ---------------------- SAFE EXPLAIN ----------------------
// We return a simplified operator tree with estimated rows/cost only.
// (In real PG we'd call EXPLAIN (FORMAT JSON). Here we keep it simple.)
type PgPlanNode = {
  "Node Type": string;
  "Plan Rows"?: number;
  "Total Cost"?: number;
  "Plans"?: PgPlanNode[];
  [k: string]: any;
};

function redactPgNode(n: PgPlanNode): any {
  const out: any = { op: n["Node Type"] || "Op" };
  if (typeof n["Plan Rows"] === "number") out.estimatedRows = n["Plan Rows"];
  if (typeof n["Total Cost"] === "number") out.totalCost = n["Total Cost"];
  if (Array.isArray(n.Plans)) out.children = n.Plans.map(redactPgNode);
  return out;
}

function formatTree(n: any, depth = 0): string {
  const pad = "  ".repeat(depth);
  const head = `${pad}- ${n.op}${n.estimatedRows !== undefined ? ` (rows≈${n.estimatedRows})` : ""}${n.totalCost !== undefined ? ` (cost≈${n.totalCost})` : ""}`;
  const kids = (n.children || []).map((c: any) => formatTree(c, depth + 1));
  return [head, ...kids].join("\n");
}

// ---------------------- MCP SERVER -----------------------
const server = new McpServer({ name: "mcp-safesql", version: "0.1.0" });

// A small resource to introspect config from clients
server.resource(
  "safesql://config",
  {
    name: "db-config",
    description: "Database type and whitelisted views",
    mimeType: "application/json"
  },
  async () => ({
    type: DB_TYPE,
    whitelist: SAFE_VIEWS,
    rowCap: MAX_ROWS
  })
);

// ---------------------- TOOLS ----------------------------
// 1) sql.query: runs a safe SELECT against whitelisted views with PII masking
server.tool(
  "sql.query",
  {
    description: "Run a read-only SELECT on whitelisted views; masks PII; caps rows.",
    inputSchema: {
      type: "object",
      properties: {
        sql: { type: "string", description: "SELECT query against whitelisted views" }
      },
      required: ["sql"]
    }
  },
  async ({ input }: ToolHandlerContext<{ sql: string }>) => {
    const raw = input.sql.trim();

    // 1) safety checks
    assertSelectOnly(raw);
    assertWhitelisted(raw);

    // 2) enforce LIMIT
    const safeSql = wrapWithLimit(raw, MAX_ROWS);

    // 3) run depending on db
    if (DB_TYPE === "sqlite") {
      const db = openSqliteRO();
      const rows: any[] = await new Promise((resolve, reject) => {
        db.all(safeSql, (err, r) => (err ? reject(err) : resolve(r || [])));
      });
      db.close();
      const masked = maskRows(rows);
      return { content: [{ type: "json", json: { rows: masked, rowsReturned: masked.length } }] };
    } else if (DB_TYPE === "postgres") {
      const rows = await withPgClient(async c => {
        const res = await c.query(safeSql);
        return res.rows || [];
      });
      const masked = maskRows(rows);
      return { content: [{ type: "json", json: { rows: masked, rowsReturned: masked.length } }] };
    } else {
      throw new Error(`Unsupported DB_TYPE: ${DB_TYPE}`);
    }
  }
);

// 2) sql.explain_safe: returns a redacted plan (operator tree only)
server.tool(
  "sql.explain_safe",
  {
    description: "Show a redacted query plan (operator tree + estimates), without revealing table/index names.",
    inputSchema: {
      type: "object",
      properties: {
        sql: { type: "string", description: "SELECT query to explain" }
      },
      required: ["sql"]
    }
  },
  async ({ input }: ToolHandlerContext<{ sql: string }>) => {
    const raw = input.sql.trim();
    assertSelectOnly(raw);
    assertWhitelisted(raw);

    // NOTE: For SQLite, we’ll fake a tiny 'operator tree' by using the parser to infer a generic plan.
    // For Postgres, a real app would call: EXPLAIN (FORMAT JSON) <safeSql> and then redact fields.
    // Here, to keep it beginner-friendly and cross-db, we produce a generic operator description.
    const genericTree = { op: "Select", children: [{ op: "Scan" }] };
    const text = formatTree(genericTree);

    return {
      content: [
        { type: "text", text: "This is a redacted, generic operator outline (beginner mode):" },
        { type: "text", text }
      ]
    };
  }
);

// ---------------------- START ----------------------------
const transport = new StdioServerTransport();
server.connect(transport);
