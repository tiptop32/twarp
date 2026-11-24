const allowed = ["mcp__twarp_gateway_ip_add", "mcp__twarp_gateway_ip_remove", "mcp__twarp_gateway_ip_list"];

export default function (pi) {
  pi.on("tool_call", async event => {
    if (!allowed.includes(event.toolName)) {
      return { block: true, reason: "Only the three twarp gateway MCP tools are permitted." };
    }
  });
  pi.on("agent_start", async () => {
    const available = new Set(pi.getAllTools().map(tool => tool.name));
    const missing = allowed.filter(name => !available.has(name));
    if (missing.length) throw new Error(`missing required MCP tools: ${missing.join(", ")}`);
    await pi.setActiveTools(allowed);
    console.error("MCP_EVAL_TOOLS_RESTRICTED");
  });
}
