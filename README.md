# Flight Recorder

When an agent run goes wrong, the chat log rarely shows why. Flight Recorder records a session through Hermes hooks (`on_session_start`, `pre_llm_call`, `post_api_request`, `post_tool_call`, `post_llm_call`): your requests, each model call (model, provider, tokens, seconds, finish reason, a text excerpt), and each tool call with arguments, a bounded result, duration and whether it failed. API keys, tokens and private-key blocks are redacted by pattern before anything is written.

- `flight_export` writes one self-contained HTML file: a colored timeline strip (tools, model calls, your messages, failures), a scrub slider and arrow keys, filters (tools, model, user, failures), search, and expandable arguments and results. It loads nothing from the network (a content-security policy forbids it) and embeds data so recorded text cannot inject script.
- `flight_summary` gives counts, tokens, time, per-tool calls and failures, the slowest tools, and markers: the **first failure**, **loops** (the same tool with identical arguments three or more times), **retries** right after a failure, and long waits.
- `flight_fork_brief` turns the history up to a chosen step into a short brief to start a fresh session from that point.
- `flight_list` lists recorded sessions.

Limits: redaction is pattern based and will miss secrets it does not recognize, so review an export before sharing; results are truncated to 2,000 characters and a session keeps at most 5,000 events or 20 MB; failure detection uses `exit_code`, an `error` field or Hermes's status; token counts come from the provider's usage fields when present; a fork brief is recorded text, not a restore of the earlier session's state; auxiliary model calls (titles, compression) are not recorded. Recording is local, in the plugin's data folder; nothing is sent anywhere. A recorder error never interrupts the agent.
