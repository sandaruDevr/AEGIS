# Agentic AI Web Assistant

A browser extension that provides an agentic AI chat panel with direct browser-level access. The AI can read, analyze, modify, and scrape web pages, execute scripts, create files, and more — all through tool calling with OpenRouter LLMs.

## Architecture

```
manifest.json
src/
├── background/
│   ├── service-worker.js    # Extension entry point, message routing
│   ├── agent-loop.js        # Core agentic loop (ReAct pattern with tool calling)
│   ├── openrouter.js        # OpenRouter API client (streaming, model listing)
│   └── tool-executor.js     # Tool dispatcher (content script vs background)
├── content/
│   └── content-script.js    # DOM tool implementations (page context)
├── tools/
│   └── definitions.js       # Tool schemas for LLM + categorization
├── sidepanel/
│   ├── sidepanel.html       # Chat UI
│   ├── sidepanel.css        # Modern dark theme styles
│   └── sidepanel.js         # Chat logic, markdown rendering, messaging
└── shared/
    └── constants.js         # Message types, storage keys, system prompt
```

## Agentic Loop

The agent uses a **ReAct-style loop**:

1. User sends message → injected with current page context
2. System prompt + conversation + tool definitions → OpenRouter API
3. LLM streams response (text + tool calls)
4. Tool calls are executed (in content script or background)
5. Tool results fed back to LLM
6. Repeat until LLM gives final response (max 15 rounds)

## Available Tools

| Tool | Description |
|------|-------------|
| `get_page_info` | URL, title, meta tags, viewport, language |
| `read_page_structure` | Hierarchical DOM tree outline |
| `read_page_html` | Raw HTML of page or element |
| `read_page_text` | Extracted text content |
| `read_element` | Detailed element info (attributes, styles, position) |
| `query_selector_all` | Find elements matching selector |
| `modify_element` | Change text, HTML, attributes, or styles |
| `inject_style` | Inject CSS stylesheet into page |
| `execute_script` | Run arbitrary JavaScript on page |
| `extract_data` | Structured data extraction (scraping schema) |
| `create_file` | Create and download file |
| `make_request` | HTTP request to external URL |
| `screenshot` | Capture page or element screenshot |
| `scroll_page` | Scroll to position or element |
| `click_element` | Simulate click on element |
| `wait` | Wait for dynamic content |

## Installation

1. Get an OpenRouter API key from [openrouter.ai/keys](https://openrouter.ai/keys)
2. Open Chrome and navigate to `chrome://extensions`
3. Enable **Developer mode** (top right toggle)
4. Click **Load unpacked** and select this project folder
5. Click the extension icon to open the side panel
6. Click the settings (gear) icon and paste your OpenRouter API key
7. Select a model from the dropdown
8. Start chatting with the agent

## Usage Examples

- **Analyze page structure**: "Analyze this page's structure and tell me the main content sections"
- **Scrape data**: "Extract all product names and prices from this page and save to JSON"
- **Write scraping scripts**: "Read the page content and write a Python scraping script for this type of page"
- **Modify page styling**: "Change the background to dark theme and adjust text colors"
- **Execute scripts**: "Run a script that highlights all links on this page"
- **Debug**: "Find all elements with inline styles and list them"

## Configuration

- **API Key**: Stored locally in `chrome.storage.local`
- **Model**: Dynamically selectable from OpenRouter's model list
- **Temperature**: Adjustable (0-2, default 0.7)
- **System Prompt**: Customizable (defaults to agentic system prompt)
- **Conversation History**: Last 50 messages persisted across sessions

## Requirements

- Chrome/Edge browser with Manifest V3 support
- OpenRouter API key
- Active internet connection

## Tech Stack

- **Manifest V3** browser extension
- **ES Modules** throughout (no build step required)
- **OpenRouter API** for LLM access (OpenAI-compatible tool calling)
- **Vanilla JS** with modern CSS (no framework dependencies)
