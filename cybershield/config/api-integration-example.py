"""
CyberShield Analytics — Claude API Integration Example
Import this pattern into any Python application to wire up the multi-agent system.

Usage:
  1. Set ANTHROPIC_API_KEY environment variable
  2. Place cybershield/ directory in your project
  3. Call invoke_agent(agent_name, user_message) to interact with any agent
  4. Call sarge_briefing() for the daily coordinator summary

Requires: pip install anthropic
"""

import os
import json
from pathlib import Path
import anthropic

CYBERSHIELD_DIR = Path(__file__).parent.parent  # adjust to your structure
AGENTS_DIR = CYBERSHIELD_DIR / "agents"
CONFIG_DIR = CYBERSHIELD_DIR / "config"

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

# Model assignments per agent (from orchestration.json)
AGENT_MODELS = {
    "sarge": "claude-opus-4-7",
    "netwatch": "claude-sonnet-4-6",
    "vulnscan": "claude-sonnet-4-6",
    "ironclad": "claude-opus-4-7",
    "complybot": "claude-sonnet-4-6",
    "patchmaster": "claude-haiku-4-5",
    "certsentry": "claude-haiku-4-5",
    "cloudguard": "claude-sonnet-4-6",
    "incidentbot": "claude-opus-4-7",
    "darkeye": "claude-sonnet-4-6",
    "idguard": "claude-sonnet-4-6",
}

# Maps agent name to system prompt file
AGENT_PROMPTS = {
    "sarge": "sarge-system-prompt.md",
    "netwatch": "netwatch-system-prompt.md",
    "vulnscan": "vulnscan-system-prompt.md",
    "ironclad": "ironclad-system-prompt.md",
    "complybot": "complybot-system-prompt.md",
    "patchmaster": "patchmaster-system-prompt.md",
    "certsentry": "certsentry-system-prompt.md",
    "cloudguard": "cloudguard-system-prompt.md",
    "incidentbot": "incidentbot-system-prompt.md",
    "darkeye": "darkeye-system-prompt.md",
    "idguard": "idguard-system-prompt.md",
}


def load_system_prompt(agent_name: str) -> str:
    prompt_file = AGENTS_DIR / AGENT_PROMPTS[agent_name]
    return prompt_file.read_text()


def invoke_agent(agent_name: str, user_message: str, context: str = "") -> str:
    """
    Invoke a specific CyberShield agent with a message.

    Args:
        agent_name: One of the agent keys in AGENT_MODELS
        user_message: The task or query for the agent
        context: Optional additional context (e.g., raw log data, alert payload)

    Returns:
        Agent response as a string
    """
    if agent_name not in AGENT_MODELS:
        raise ValueError(f"Unknown agent: {agent_name}. Valid agents: {list(AGENT_MODELS.keys())}")

    system_prompt = load_system_prompt(agent_name)

    full_message = user_message
    if context:
        full_message = f"{user_message}\n\nContext/Data:\n```\n{context}\n```"

    response = client.messages.create(
        model=AGENT_MODELS[agent_name],
        max_tokens=4096,
        system=system_prompt,
        messages=[
            {"role": "user", "content": full_message}
        ]
    )

    return response.content[0].text


def sarge_briefing(agent_reports: dict = None) -> str:
    """
    Generate a Sarge daily briefing.

    Args:
        agent_reports: Optional dict of {agent_name: report_text} to include

    Returns:
        Formatted daily briefing from Sarge
    """
    briefing_input = "Generate today's daily security briefing."

    if agent_reports:
        reports_text = "\n\n".join([
            f"=== {name.upper()} REPORT ===\n{report}"
            for name, report in agent_reports.items()
        ])
        briefing_input += f"\n\nAgent reports received:\n{reports_text}"

    return invoke_agent("sarge", briefing_input)


def route_alert(alert_data: dict) -> tuple[str, str]:
    """
    Route a raw alert to the appropriate agent using Sarge as coordinator.

    Returns:
        (agent_name, agent_response) tuple
    """
    alert_json = json.dumps(alert_data, indent=2)

    # Sarge determines routing
    routing_response = invoke_agent(
        "sarge",
        "Determine which agent should handle this alert and respond with ONLY the agent name (lowercase, no explanation):",
        alert_json
    )

    agent_name = routing_response.strip().lower()

    # Validate agent name
    if agent_name not in AGENT_MODELS:
        agent_name = "sarge"  # fallback to coordinator

    # Route to determined agent
    agent_response = invoke_agent(
        agent_name,
        f"Analyze and respond to this alert:",
        alert_json
    )

    return agent_name, agent_response


def wazuh_alert_handler(wazuh_alert: dict) -> dict:
    """
    Process a Wazuh alert through the appropriate CyberShield agent.

    Wire this to your Wazuh webhook or custom alert integration.

    Args:
        wazuh_alert: Parsed Wazuh alert JSON

    Returns:
        dict with agent_name, response, severity, recommended_action
    """
    rule_id = wazuh_alert.get("rule", {}).get("id", 0)
    rule_level = wazuh_alert.get("rule", {}).get("level", 0)
    rule_groups = wazuh_alert.get("rule", {}).get("groups", [])

    # Pre-route based on rule groups (faster than asking Sarge for low-level alerts)
    if any(g in rule_groups for g in ["authentication_failure", "authentication_success", "pam"]):
        agent = "idguard"
    elif any(g in rule_groups for g in ["network", "firewall", "ids", "intrusion_detection"]):
        agent = "netwatch"
    elif any(g in rule_groups for g in ["vulnerability-detector", "sca"]):
        agent = "vulnscan"
    elif any(g in rule_groups for g in ["dlp", "usb", "exfiltration"]):
        agent = "ironclad"
    elif any(g in rule_groups for g in ["amazon-s3", "aws-cloudtrail", "azure", "gcp"]):
        agent = "cloudguard"
    elif rule_level >= 12:
        # High-severity unknown → Sarge coordinates
        agent = "sarge"
    else:
        agent = "sarge"

    response = invoke_agent(
        agent,
        "Analyze this Wazuh alert and provide your assessment:",
        json.dumps(wazuh_alert, indent=2)
    )

    return {
        "alert_id": wazuh_alert.get("id"),
        "agent_handled": agent,
        "wazuh_level": rule_level,
        "response": response,
        "timestamp": wazuh_alert.get("timestamp")
    }


# ─────────────────────────────────────────────────────────────────
# EXAMPLE: Daily briefing workflow
# ─────────────────────────────────────────────────────────────────

def run_daily_briefing_workflow():
    """
    Example: Collect reports from each Tier 1 agent, then feed to Sarge.
    Run this on a cron schedule at 07:45 to have briefing ready by 08:00.
    """
    tier1_agents = ["netwatch", "vulnscan", "ironclad"]
    reports = {}

    for agent in tier1_agents:
        print(f"Collecting {agent} report...")
        reports[agent] = invoke_agent(
            agent,
            "Generate your daily status report for Sarge. Include: summary of activity, "
            "any open findings, completed tasks, and anything requiring Sarge attention."
        )

    print("Generating Sarge briefing...")
    briefing = sarge_briefing(reports)

    print("\n" + "="*60)
    print("CYBERSHIELD DAILY BRIEFING")
    print("="*60)
    print(briefing)

    return briefing


# ─────────────────────────────────────────────────────────────────
# EXAMPLE: Wazuh webhook endpoint (Flask)
# Deploy on your Hostinger VPS alongside Wazuh Manager
# ─────────────────────────────────────────────────────────────────

"""
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/cybershield/wazuh-webhook", methods=["POST"])
def wazuh_webhook():
    alert = request.json
    result = wazuh_alert_handler(alert)

    # Log result, send notification if high severity
    if alert.get("rule", {}).get("level", 0) >= 10:
        # Send to Slack/Teams/PagerDuty here
        pass

    return jsonify(result)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
"""


if __name__ == "__main__":
    # Quick test — invoke Sarge with a sample question
    response = invoke_agent(
        "sarge",
        "What are my top 3 security priorities this week for a domain-joined Windows 11 environment running Wazuh?"
    )
    print(response)
