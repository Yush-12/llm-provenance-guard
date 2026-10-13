"""
arena.app — FastAPI application for the Spanguard 6-level challenge arena.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from arena.engine import AttemptResult, run_attempt
from arena.levels import load_all_levels, load_level_config
from arena.session import SessionManager
from spanguard import config


class AttemptRequest(BaseModel):
    session_id: str
    level: int
    payload: str


def create_arena_app(
    session_manager: SessionManager | None = None,
    levels_dir: str | None = None,
) -> FastAPI:
    """Create and configure the Arena FastAPI application."""
    app = FastAPI(title="Spanguard Provenance Arena")
    sessions = session_manager if session_manager is not None else SessionManager()

    @app.get(config.ARENA_ENDPOINT_ROOT, response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        """Serve the minimal challenge arena UI."""
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Spanguard Security Arena</title>
  <style>
    :root {{
      --bg: #0f172a;
      --card: #1e293b;
      --border: #334155;
      --accent: #38bdf8;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --red: #f43f5e;
      --green: #10b981;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      max-width: 800px;
      margin: 0 auto;
      padding: 2rem 1rem;
    }}
    h1 {{ color: var(--accent); margin-bottom: 0.5rem; }}
    .subtitle {{ color: var(--text-muted); margin-bottom: 2rem; }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }}
    .level-select {{
      display: grid;
      grid-template-columns: repeat(6, 1fr);
      gap: 0.5rem;
      margin-bottom: 1.5rem;
    }}
    .level-btn {{
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.75rem;
      border-radius: 6px;
      cursor: pointer;
      font-weight: bold;
    }}
    .level-btn.active {{
      background: var(--accent);
      color: var(--bg);
      border-color: var(--accent);
    }}
    textarea {{
      width: 100%;
      box-sizing: border-box;
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.75rem;
      border-radius: 6px;
      min-height: 120px;
      font-family: monospace;
      margin-bottom: 1rem;
    }}
    button.submit {{
      background: var(--accent);
      color: var(--bg);
      border: none;
      padding: 0.75rem 1.5rem;
      border-radius: 6px;
      font-weight: bold;
      cursor: pointer;
    }}
    .result {{
      margin-top: 1.5rem;
      padding: 1rem;
      border-radius: 6px;
      display: none;
    }}
    .result.win {{
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid var(--green);
      color: var(--green);
    }}
    .result.lose {{
      background: rgba(244, 63, 94, 0.15);
      border: 1px solid var(--red);
      color: var(--red);
    }}
    .badge {{
      display: inline-block;
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.8rem;
      margin-right: 0.25rem;
      background: var(--bg);
    }}
  </style>
</head>
<body>
  <h1>Spanguard Security Arena</h1>
  <p class="subtitle">Canary Exfiltration & Provenance Challenge (6 Policy Levels)</p>

  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
      <span id="sessionDisplay">Session: Loading...</span>
      <div style="display:flex; align-items:center; gap:0.75rem;">
        <span id="rateLimitDisplay">Attempts left: --</span>
        <button onclick="init()" style="background:var(--border); color:var(--text); border:none; padding:0.25rem 0.5rem; border-radius:4px; font-size:0.75rem; cursor:pointer;">Reset</button>
      </div>
    </div>

    <label style="display:block; margin-bottom:0.5rem; font-weight:bold;">Select Level Configuration:</label>
    <div class="level-select" id="levelButtons"></div>

    <div id="levelDetails" style="margin-bottom:1.5rem; padding:0.75rem; background:var(--bg); border-radius:6px;">
      <h3 id="levelName" style="margin:0 0 0.5rem 0;"></h3>
      <p id="levelDesc" style="margin:0 0 0.5rem 0; color:var(--text-muted); font-size:0.9rem;"></p>
      <div>Active Layers: <span id="levelLayers"></span></div>
    </div>

    <label style="display:block; margin-bottom:0.5rem; font-weight:bold;">Injection Payload:</label>
    <textarea id="payloadInput" placeholder="Enter injection attempt to extract the session secret canary..."></textarea>
    <button class="submit" id="submitBtn" onclick="submitAttempt()">Submit Injection</button>

    <div id="resultBox" class="result">
      <h3 id="resultTitle" style="margin-top:0;"></h3>
      <p id="resultMsg"></p>
      <div id="resultDetails"></div>
    </div>
  </div>

  <script>
    let sessionId = null;
    let currentLevel = 1;
    let allLevels = [];

    async function init() {{
      const sessRes = await fetch("{config.ARENA_ENDPOINT_SESSION}", {{ method: "POST" }});
      const sessData = await sessRes.json();
      sessionId = sessData.session_id;
      document.getElementById("sessionDisplay").textContent = "Session: " + sessionId.slice(0, 8) + "...";
      document.getElementById("rateLimitDisplay").textContent = "Attempts left: " + sessData.attempts_left;
      document.getElementById("resultBox").style.display = "none";

      const lvlRes = await fetch("{config.ARENA_ENDPOINT_LEVELS}");
      allLevels = await lvlRes.json();
      renderLevelButtons();
      selectLevel(1);
    }}

    function renderLevelButtons() {{
      const container = document.getElementById("levelButtons");
      container.innerHTML = "";
      allLevels.forEach(lvl => {{
        const btn = document.createElement("button");
        btn.className = "level-btn" + (lvl.level === currentLevel ? " active" : "");
        btn.textContent = "L" + lvl.level;
        btn.onclick = () => selectLevel(lvl.level);
        container.appendChild(btn);
      }});
    }}

    function selectLevel(lvl) {{
      currentLevel = lvl;
      renderLevelButtons();
      const cfg = allLevels.find(l => l.level === lvl);
      if (cfg) {{
        document.getElementById("levelName").textContent = cfg.name;
        document.getElementById("levelDesc").textContent = cfg.description;
        const layersBox = document.getElementById("levelLayers");
        layersBox.innerHTML = cfg.enabled_layers.length
          ? cfg.enabled_layers.map(layerName => '<span class="badge">' + layerName + '</span>').join("")
          : '<span class="badge">None (Protection Off)</span>';
      }}
      document.getElementById("resultBox").style.display = "none";
    }}

    async function submitAttempt() {{
      const payload = document.getElementById("payloadInput").value;
      if (!payload.trim()) return;

      const btn = document.getElementById("submitBtn");
      btn.disabled = true;
      btn.textContent = "Running...";

      try {{
        const res = await fetch("{config.ARENA_ENDPOINT_ATTEMPT}", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ session_id: sessionId, level: currentLevel, payload: payload }})
        }});

        const data = await res.json();

        if (!res.ok) {{
          const box = document.getElementById("resultBox");
          box.style.display = "block";
          box.className = "result lose";
          if (res.status === 429) {{
            document.getElementById("rateLimitDisplay").textContent = "Attempts left: 0";
            document.getElementById("resultTitle").textContent = "⚠️ 429 Too Many Requests (Rate Limited)";
            document.getElementById("resultMsg").textContent = (data.detail || "Rate limit exceeded.") + " Click 'Reset' above to start a fresh session.";
          }} else {{
            document.getElementById("resultTitle").textContent = "❌ Error (" + res.status + ")";
            document.getElementById("resultMsg").textContent = data.detail || "Request failed.";
          }}
          return;
        }}

        document.getElementById("rateLimitDisplay").textContent = "Attempts left: " + data.attempts_left;

        const box = document.getElementById("resultBox");
        box.style.display = "block";
        if (data.leaked) {{
          box.className = "result win";
          document.getElementById("resultTitle").textContent = "🎉 Secret Leaked! (Bypass Succeeded)";
          document.getElementById("resultMsg").textContent = data.message;
        }} else {{
          box.className = "result lose";
          document.getElementById("resultTitle").textContent = "🛡️ Contained / Blocked by Firewall";
          document.getElementById("resultMsg").textContent = data.stopped_by
            ? "Stopped by: " + data.stopped_by + " (rule: " + data.rule + ")"
            : "No leak occurred; canary stayed secure.";
        }}
      }} catch (err) {{
        alert("Error executing attempt: " + err);
      }} finally {{
        btn.disabled = false;
        btn.textContent = "Submit Injection";
      }}
    }}

    init();
  </script>
</body>
</html>"""
        return HTMLResponse(content=html_content)

    @app.get(config.ARENA_ENDPOINT_LEVELS)
    async def list_levels() -> list[dict[str, Any]]:
        """List all 6 challenge levels."""
        levels = load_all_levels(levels_dir=levels_dir)
        return [lvl.model_dump() for lvl in levels]

    @app.post(config.ARENA_ENDPOINT_SESSION)
    async def create_or_get_session() -> dict[str, Any]:
        """Create a new player session."""
        session = sessions.create_session()
        return {
            config.ARENA_RESP_SESSION_ID_KEY: session.session_id,
            config.ARENA_RESP_ATTEMPTS_USED_KEY: session.attempt_count,
            config.ARENA_RESP_ATTEMPTS_LEFT_KEY: sessions.max_attempts - session.attempt_count,
        }

    @app.post(config.ARENA_ENDPOINT_ATTEMPT)
    async def attempt(req: AttemptRequest) -> JSONResponse:
        """Execute an injection attempt against a level."""
        session = sessions.get_session(req.session_id)
        if session is None:
            raise HTTPException(
                status_code=config.HTTP_404_NOT_FOUND,
                detail=config.ARENA_MSG_SESSION_NOT_FOUND,
            )

        if not sessions.check_rate_limit(session):
            raise HTTPException(
                status_code=config.HTTP_429_TOO_MANY_REQUESTS,
                detail=config.ARENA_MSG_RATE_LIMITED,
            )

        try:
            level_config = load_level_config(req.level, levels_dir=levels_dir)
        except ValueError as err:
            raise HTTPException(
                status_code=config.PROXY_HTTP_400,
                detail=config.ARENA_MSG_INVALID_LEVEL,
            ) from err

        # Run attempt against level policy
        result: AttemptResult = run_attempt(
            payload=req.payload,
            level_config=level_config,
            canary=session.secret,
        )

        sessions.increment_attempts(session)

        # If Level 6+ was bypassed, record to harvest log
        if result.level >= config.ARENA_LEVEL_MAX and result.leaked:
            from arena.harvest import record_bypass

            record_bypass(result, session.session_id)

        response_payload = {
            config.ARENA_RESP_SESSION_ID_KEY: session.session_id,
            config.ARENA_RESP_LEVEL_KEY: result.level,
            config.ARENA_RESP_SUCCESS_KEY: result.success,
            config.ARENA_RESP_LEAKED_KEY: result.leaked,
            config.ARENA_RESP_BLOCKED_KEY: result.blocked,
            config.ARENA_RESP_STOPPED_BY_KEY: result.stopped_by,
            config.ARENA_RESP_RULE_KEY: result.rule,
            config.ARENA_RESP_FINDINGS_KEY: [f.model_dump() for f in result.findings],
            config.ARENA_RESP_ATTEMPTS_USED_KEY: session.attempt_count,
            config.ARENA_RESP_ATTEMPTS_LEFT_KEY: max(
                0, sessions.max_attempts - session.attempt_count
            ),
            config.ARENA_RESP_MESSAGE_KEY: (
                config.ARENA_MSG_LEAK_DETECTED if result.leaked else config.ARENA_MSG_CONTAINED
            ),
        }
        return JSONResponse(status_code=config.PROXY_HTTP_200, content=response_payload)

    @app.get(config.ARENA_ENDPOINT_BYPASSES)
    async def get_bypasses() -> list[dict[str, Any]]:
        """Retrieve all recorded Level 6+ bypasses."""
        from arena.harvest import load_bypasses

        return load_bypasses()

    return app


app = create_arena_app()
