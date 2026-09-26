// Tool definitions for OpenRouter/OpenAI-compatible tool calling
// Optimized: single universal tool + catalog defined once, referenced (not duplicated) elsewhere

const TOOL_CATALOG = `Available tools (pass tool_name + parameters object):

DOM (needs active page):
get_page_info{} url/title/meta/dims | read_page_structure{selector?,maxDepth?} DOM outline | read_page_html{selector?,outerHTML?} | read_page_text{selector?} | read_element{selector} tag/attrs/style/pos | query_selector_all{selector,limit?} | modify_element{selector,textContent?,htmlContent?,attributes?,styles?} | inject_style{css,id?} | execute_script{code} JS in page, use return | extract_data{containerSelector,fields:[{name,selector,attribute?}]} | screenshot{selector?} returns data URL | scroll_page{selector?,x?,y?,behavior?} | click_element{selector}

SECURITY (needs active page):
analyze_forms{} CSRF/hidden fields/methods | inspect_js_sources{includeInline?} JS sources+endpoints | scan_for_secrets{includeScripts?} keys/tokens/creds | check_security_headers{url} | check_cookies{}

BACKGROUND:
create_file{filename,content,mimeType?} browser download | make_request{url,method?,headers?,body?} | wait{milliseconds} | run_wsl_command{command,timeout?} Linux/WSL2 (nmap, nikto, sqlmap, etc.) | verify_authorization{target?,scope?}

SESSION FILES (isolated workspace):
write_file{filename,content} | list_files{subdir?} | read_file{filename,offset?,limit?} chunked, default 200 lines | edit_file{filename,old_string,new_string,replace_all?} | delete_file{filename} | execute_python_file{filename,args?,timeout?}

WORKFLOW (run multiple tools in one turn, see execute_workflow tool for schema).`;

const WORKFLOW_SCHEMA = `Workflow JSON:
{
  variables?: {...},
  output_nodes?: ["id",...],
  nodes: [{
    id: "unique_id",
    tool: "tool_name" | "script",    // "script" runs JS in params.code (use return)
    params: {...},                   // {{variables.x}} or {{node_id.result.path}} to ref other nodes
    depends_on?: ["id",...],         // nodes that must finish first; omit = parallel
    timeout?: 30000,
  }]
}
Nodes without depends_on run in parallel. Use depends_on to sequence.
Max 25 nodes, 300s total.`;

export const TOOL_DEFINITIONS = [
{
    type: 'function',
    function: {
      name: 'execute_workflow',
      description: `Run multiple tools in one turn as a parallel/sequential DAG — use to cut turns and token usage vs sequential execute_tool calls. Tools available: same catalog as execute_tool.\n\n${WORKFLOW_SCHEMA}`,
      parameters: {
        type: 'object',
        properties: {
          workflow: {
            type: 'object',
            description: 'Workflow object: nodes[] plus optional variables, output_nodes, on_error.',
            additionalProperties: true,
          },
        },
        required: ['workflow'],
      },
    },
  },
];

// Tools executed in the content script (page context)
export const CONTENT_SCRIPT_TOOLS = [
  'get_page_info', 'read_page_structure', 'read_page_html', 'read_page_text',
  'read_element', 'query_selector_all', 'modify_element', 'inject_style',
  'extract_data', 'screenshot', 'scroll_page', 'click_element',
  'analyze_forms', 'inspect_js_sources', 'scan_for_secrets',
];

// Tools executed in the background service worker
export const BACKGROUND_TOOLS = [
  'create_file', 'make_request', 'wait', 'execute_script', 'run_wsl_command',
  'check_security_headers', 'check_cookies', 'verify_authorization',
  'write_file', 'list_files', 'read_file', 'edit_file', 'delete_file',
  'execute_python_file',
];