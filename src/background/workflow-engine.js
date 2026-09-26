// Workflow Engine — DAG-based multi-tool execution in a single LLM turn
// Nodes declare dependencies via `depends_on` — engine topologically sorts automatically.
// Nodes with no dependencies (or same dependency level) run in parallel.
// Nodes can reference outputs of any dependency via {{node_id.result}}.
// Backward compat: `order` field still supported (converted to implicit deps).

import vm from 'node:vm';

const MAX_NODES = 25;
const MAX_SCRIPT_TIMEOUT_MS = 5000;
const DEFAULT_NODE_TIMEOUT_MS = 30000;
const GLOBAL_TIMEOUT_MS = 300000;
const MAX_INTERPOLATION_DEPTH = 10;
const DEFAULT_LLM_TRUNCATE = 4000;

export class WorkflowEngine {
  constructor(toolExecutor) {
    this.executor = toolExecutor;
  }

  async execute(workflow) {
    const validation = this._validate(workflow);
    if (!validation.ok) {
      return { success: false, error: validation.error };
    }

    const { variables, nodes, output_nodes, on_error } = workflow;
    const nodeMap = new Map();
    for (const n of nodes) nodeMap.set(n.id, n);

    // Topologically sort nodes by depends_on (falls back to order for compat)
    const orderGroups = this._topologicalSort(nodes);

    // Results stored here — full untruncated data for interpolation
    const results = {};
    // LLM-facing results — truncated per node's llm_truncate
    const llmResults = {};

    const globalStart = Date.now();

    try {
      for (const [order, groupNodes] of orderGroups) {
        // Check global timeout
        if (Date.now() - globalStart > GLOBAL_TIMEOUT_MS) {
          return this._buildResult(llmResults, output_nodes, results, {
            error: 'Global workflow timeout exceeded',
          });
        }

        // Execute all nodes in this order group in parallel
        const promises = groupNodes.map((node) =>
          this._executeNode(node, variables, results).catch((err) => ({
            success: false,
            error: err.message,
          }))
        );

        const groupResults = await Promise.all(promises);

        // Store results — full data for interpolation, truncated for LLM
        for (let i = 0; i < groupNodes.length; i++) {
          const node = groupNodes[i];
          const result = groupResults[i];

          // Full result for downstream interpolation
          results[node.id] = result;

          // Truncated result for LLM
          const truncateSize = node.llm_truncate ?? DEFAULT_LLM_TRUNCATE;
          llmResults[node.id] = this._truncateForLLM(result, truncateSize);

          // Error policy
          if (!result.success && on_error === 'stop') {
            return this._buildResult(llmResults, output_nodes, results, {
              error: `Node "${node.id}" failed, workflow stopped`,
              stopped_at: node.id,
            });
          }
        }
      }

      return this._buildResult(llmResults, output_nodes, results);
    } catch (err) {
      return this._buildResult(llmResults, output_nodes, results, {
        error: `Workflow execution error: ${err.message}`,
      });
    }
  }

  // Execute a single node
  async _executeNode(node, variables, priorResults) {
    const timeout = node.timeout ?? DEFAULT_NODE_TIMEOUT_MS;

    // Script node — run in VM sandbox with values as context variables (not string-interpolated into code)
    if (node.tool === 'script') {
      return await this._executeScriptNode(node, variables, priorResults, timeout);
    }

    // Tool node — interpolate params then delegate to ToolExecutor
    let interpolatedParams;
    try {
      interpolatedParams = this._interpolate(node.params, variables, priorResults, 0);
    } catch (interpErr) {
      return {
        success: false,
        error: `Interpolation failed for node "${node.id}": ${interpErr.message}`,
      };
    }

    // Tool node — delegate to ToolExecutor
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`Node "${node.id}" timed out after ${timeout}ms`)), timeout)
    );

    try {
      const result = await Promise.race([
        this.executor.executeTool(node.tool, interpolatedParams),
        timeoutPromise,
      ]);
      return result;
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  // Execute script node in a sandboxed VM
  // {{...}} references in code are replaced with safe variable names and values passed as context
  async _executeScriptNode(node, variables, results, timeout) {
    const rawCode = node.params?.code;
    if (!rawCode || typeof rawCode !== 'string') {
      return { success: false, error: 'Script node requires "code" parameter' };
    }

    // Extract all {{...}} references from the code
    const refPattern = /\{\{([^}]+)\}\}/g;
    const refs = [];
    let match;
    while ((match = refPattern.exec(rawCode)) !== null) {
      refs.push(match[1].trim());
    }

    // Build VM context with resolved values as variables
    const ctx = {
      JSON, Math, String, Array, Object, Number, Boolean, Date, RegExp,
      parseInt, parseFloat, isNaN,
      console: { log: () => {}, error: () => {}, warn: () => {} },
    };

    // Replace each {{...}} with a safe variable name and add resolved value to context
    let safeCode = rawCode;
    const seen = new Map(); // ref -> varName (dedup)

    for (let i = 0; i < refs.length; i++) {
      const ref = refs[i];
      const varName = `__ref_${i}`;

      // Resolve the reference value
      const parts = ref.split('.');
      let val;
      if (parts[0] === 'variables') {
        val = variables;
        for (let j = 1; j < parts.length; j++) {
          if (val == null) break;
          val = val[parts[j]];
        }
      } else {
        const nodeResult = results[parts[0]];
        if (!nodeResult) {
          return { success: false, error: `Script in node "${node.id}" references unknown node "${parts[0]}"` };
        }
        val = nodeResult;
        for (let j = 1; j < parts.length; j++) {
          if (val == null) break;
          val = val[parts[j]];
        }
      }

      ctx[varName] = val;

      // Replace all occurrences of this exact {{ref}} with the variable name
      const escapedRef = ref.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      safeCode = safeCode.replace(new RegExp(`\{\{${escapedRef}\}\}`, 'g'), varName);
    }

    try {
      const wrappedCode = `(function() { ${safeCode} })()`;
      const script = new vm.Script(wrappedCode, { filename: `workflow:${node.id}` });
      const context = vm.createContext(ctx);
      const result = script.runInContext(context, {
        timeout: Math.min(timeout, MAX_SCRIPT_TIMEOUT_MS),
        displayErrors: true,
      });

      return { success: true, result: result ?? null };
    } catch (err) {
      return { success: false, error: `Script error in node "${node.id}": ${err.message}` };
    }
  }

  // Recursively interpolate {{...}} references in any value
  _interpolate(value, variables, results, depth) {
    if (depth > MAX_INTERPOLATION_DEPTH) {
      throw new Error('Max interpolation depth exceeded');
    }

    if (typeof value === 'string') {
      return this._interpolateString(value, variables, results, depth);
    }

    if (Array.isArray(value)) {
      return value.map((v) => this._interpolate(v, variables, results, depth));
    }

    if (value && typeof value === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(value)) {
        out[k] = this._interpolate(v, variables, results, depth);
      }
      return out;
    }

    return value;
  }

  _interpolateString(str, variables, results, depth) {
    // Match {{variables.path}} or {{node_id.result.path}}
    return str.replace(/\{\{([^}]+)\}\}/g, (match, ref) => {
      const trimmed = ref.trim();
      const parts = trimmed.split('.');

      if (parts.length < 2) {
        return match; // Invalid reference, leave as-is
      }

      let val;

      if (parts[0] === 'variables') {
        val = variables;
        for (let i = 1; i < parts.length; i++) {
          if (val == null) break;
          val = val[parts[i]];
        }
      } else {
        // Node reference: {{node_id.result}} or {{node_id.result.path}}
        const nodeId = parts[0];
        const nodeResult = results[nodeId];
        if (!nodeResult) {
          throw new Error(`Node "${nodeId}" not found or not yet executed`);
        }
        // Start from parts[1] (should be "result" or "error" etc.)
        val = nodeResult;
        for (let i = 1; i < parts.length; i++) {
          if (val == null) break;
          val = val[parts[i]];
        }
      }

      if (val === undefined || val === null) {
        return '';
      }

      if (typeof val === 'string') {
        // Nested interpolation for string values
        return this._interpolateString(val, variables, results, depth + 1);
      }

      // For non-string values embedded in a string context, JSON-ify
      // But if the entire string is just the reference, return the raw value
      if (str.trim() === match.trim()) {
        return val; // Return raw value — will be handled by parent interpolation
      }

      return JSON.stringify(val);
    });
  }

  // Truncate result for LLM consumption only — does not affect data flow
  _truncateForLLM(result, maxChars) {
    const str = JSON.stringify(result);
    if (str.length <= maxChars) {
      return result;
    }
    // Truncate the stringified version and parse back
    const truncated = str.substring(0, maxChars);
    // Try to find a clean cut point
    const lastBrace = truncated.lastIndexOf('}');
    const lastBracket = truncated.lastIndexOf(']');
    const cutPoint = Math.max(lastBrace, lastBracket);

    if (cutPoint > maxChars * 0.8) {
      const partial = truncated.substring(0, cutPoint + 1);
      try {
        const parsed = JSON.parse(partial);
        return { ...parsed, _truncated: true, _original_chars: str.length };
      } catch {
        // Fall through to string truncation
      }
    }

    return {
      success: result.success,
      _truncated: true,
      _original_chars: str.length,
      _preview: truncated.substring(0, maxChars) + '...[truncated]',
    };
  }

  // Compute execution level for each node via topological sort of depends_on
  // Level 0 = no dependencies (parallel). Level N = max(dep levels) + 1.
  // Backward compat: nodes with `order` but no `depends_on` get implicit deps on all lower-order nodes.
  _computeLevels(nodes) {
    const nodeMap = new Map();
    for (const n of nodes) nodeMap.set(n.id, n);

    // Build direct dependency sets
    const deps = new Map();
    for (const n of nodes) {
      const direct = new Set();
      if (Array.isArray(n.depends_on)) {
        for (const d of n.depends_on) direct.add(d);
      } else if (n.order != null) {
        // Backward compat: order-based — depend on all nodes with strictly lower order
        for (const other of nodes) {
          if (other.id !== n.id && (other.order ?? 99) < (n.order ?? 99)) {
            direct.add(other.id);
          }
        }
      }
      deps.set(n.id, direct);
    }

    // Memoized level computation with cycle detection
    const levels = new Map();
    const visiting = new Set();

    const computeLevel = (id) => {
      if (levels.has(id)) return levels.get(id);
      if (visiting.has(id)) {
        throw new Error(`Circular dependency detected involving node "${id}"`);
      }
      visiting.add(id);

      const nodeDeps = deps.get(id);
      if (nodeDeps.size === 0) {
        levels.set(id, 0);
        visiting.delete(id);
        return 0;
      }

      let maxLevel = 0;
      for (const depId of nodeDeps) {
        maxLevel = Math.max(maxLevel, computeLevel(depId) + 1);
      }
      levels.set(id, maxLevel);
      visiting.delete(id);
      return maxLevel;
    };

    for (const n of nodes) computeLevel(n.id);
    return levels;
  }

  // Group nodes by dependency level, return Map sorted by level ascending
  _topologicalSort(nodes) {
    const levels = this._computeLevels(nodes);
    const groups = new Map();
    for (const n of nodes) {
      const level = levels.get(n.id);
      if (!groups.has(level)) groups.set(level, []);
      groups.get(level).push(n);
    }
    return new Map([...groups.entries()].sort((a, b) => a[0] - b[0]));
  }

  // Validate workflow structure
  _validate(workflow) {
    if (!workflow || typeof workflow !== 'object') {
      return { ok: false, error: 'Workflow must be an object' };
    }

    if (!Array.isArray(workflow.nodes) || workflow.nodes.length === 0) {
      return { ok: false, error: 'Workflow must have a non-empty "nodes" array' };
    }

    if (workflow.nodes.length > MAX_NODES) {
      return { ok: false, error: `Workflow exceeds max node limit of ${MAX_NODES}` };
    }

    const ids = new Set();

    for (const node of workflow.nodes) {
      if (!node.id || typeof node.id !== 'string') {
        return { ok: false, error: 'Every node must have a string "id"' };
      }
      if (ids.has(node.id)) {
        return { ok: false, error: `Duplicate node id: "${node.id}"` };
      }
      ids.add(node.id);

      if (!node.tool || typeof node.tool !== 'string') {
        return { ok: false, error: `Node "${node.id}" must have a "tool" field` };
      }

      if (node.params && typeof node.params !== 'object') {
        return { ok: false, error: `Node "${node.id}" params must be an object` };
      }

      // Validate depends_on
      if (node.depends_on != null) {
        if (!Array.isArray(node.depends_on)) {
          return { ok: false, error: `Node "${node.id}" depends_on must be an array of node ids` };
        }
        for (const dep of node.depends_on) {
          if (typeof dep !== 'string') {
            return { ok: false, error: `Node "${node.id}" depends_on must be array of strings` };
          }
          if (dep === node.id) {
            return { ok: false, error: `Node "${node.id}" cannot depend on itself` };
          }
        }
      }

      // Backward compat: validate order if present
      if (node.order != null && (typeof node.order !== 'number' || node.order < 1)) {
        return { ok: false, error: `Node "${node.id}" order must be a positive number` };
      }

      if (node.llm_truncate != null && (typeof node.llm_truncate !== 'number' || node.llm_truncate < 0)) {
        return { ok: false, error: `Node "${node.id}" llm_truncate must be a non-negative number` };
      }
    }

    // Validate depends_on references exist
    for (const node of workflow.nodes) {
      if (node.depends_on) {
        for (const dep of node.depends_on) {
          if (!ids.has(dep)) {
            return { ok: false, error: `Node "${node.id}" depends_on unknown node "${dep}"` };
          }
        }
      }
    }

    // Topological sort — throws on circular deps
    let levelMap;
    try {
      levelMap = this._computeLevels(workflow.nodes);
    } catch (err) {
      return { ok: false, error: err.message };
    }

    // Validate interpolation references — referenced node must be at a lower level (runs before)
    for (const node of workflow.nodes) {
      const refs = this._extractRefs(node.params || {});
      for (const ref of refs) {
        if (ref === 'variables') continue;

        if (!ids.has(ref)) {
          return { ok: false, error: `Node "${node.id}" references unknown node "${ref}"` };
        }

        if (levelMap.get(ref) >= levelMap.get(node.id)) {
          return {
            ok: false,
            error: `Node "${node.id}" references "${ref}" but doesn't depend on it — add "${ref}" to depends_on`,
          };
        }
      }
    }

    // Validate output_nodes if provided
    if (workflow.output_nodes) {
      if (!Array.isArray(workflow.output_nodes)) {
        return { ok: false, error: 'output_nodes must be an array' };
      }
      for (const id of workflow.output_nodes) {
        if (!ids.has(id)) {
          return { ok: false, error: `output_nodes references unknown node: "${id}"` };
        }
      }
    }

    return { ok: true };
  }

  // Extract all {{node_id.*}} references from a params object
  _extractRefs(obj) {
    const refs = new Set();
    const str = JSON.stringify(obj || {});
    const matches = str.matchAll(/\{\{([^}]+)\}\}/g);
    for (const m of matches) {
      const parts = m[1].trim().split('.');
      if (parts.length >= 2) {
        refs.add(parts[0]);
      }
    }
    return refs;
  }

  // Build the final result returned to the LLM
  _buildResult(llmResults, outputNodes, fullResults, errorInfo) {
    let output;

    if (outputNodes && outputNodes.length > 0) {
      output = {};
      for (const id of outputNodes) {
        if (llmResults[id] !== undefined) {
          output[id] = llmResults[id];
        }
      }
    } else {
      output = llmResults;
    }

    const result = { success: true, results: output };

    if (errorInfo) {
      result.success = false;
      result.error = errorInfo.error;
      if (errorInfo.stopped_at) result.stopped_at = errorInfo.stopped_at;
    }

    // Summary stats
    const nodeCount = Object.keys(fullResults).length;
    const successCount = Object.values(fullResults).filter((r) => r?.success).length;
    result.summary = {
      total_nodes: nodeCount,
      succeeded: successCount,
      failed: nodeCount - successCount,
    };

    return result;
  }
}
