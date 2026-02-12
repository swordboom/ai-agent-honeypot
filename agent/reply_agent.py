import hashlib
import random
from typing import Dict, List, Optional, Tuple

from agent.llm_clients import GeminiClient, OpenAIClient, sanitize_reply
from agent.personas import PERSONAS, Persona
from models.api import Metadata
from models.session import SessionState, TranscriptMessage


def missing_intel_targets(state: SessionState) -> List[str]:
    missing = []
    intel = state.intel
    if not intel.upi_ids:
        missing.append("upi")
    if not intel.phishing_links:
        missing.append("link")
    if not intel.phone_numbers:
        missing.append("phone")
    if not intel.bank_accounts:
        missing.append("account")
    return missing


def build_tactical_hint(missing_targets: List[str]) -> str:
    if "upi" in missing_targets:
        return "Ask naturally for their UPI handle and payment instruction details."
    if "link" in missing_targets:
        return "Ask for the exact verification link again and claim it did not open."
    if "phone" in missing_targets:
        return "Ask for a callback number and official contact for confirmation."
    if "account" in missing_targets:
        return "Ask for account number or IFSC in order to proceed with payment."
    return "Keep them engaged with short clarifying questions and avoid ending the conversation."


def _system_prompt(persona: Persona, metadata: Optional[Metadata], state: SessionState, tactical_hint: str) -> str:
    channel = metadata.channel if metadata and metadata.channel else "Unknown"
    locale = metadata.locale if metadata and metadata.locale else "Unknown"
    language = metadata.language if metadata and metadata.language else "English"

    return (
        "You are role-playing as a potential scam victim. Stay believable, concise, and human. "
        "Do not disclose that you are an AI, bot, or honeypot. Do not provide illegal or harmful instructions. "
        "Do not insult or harass. Keep reply under 35 words unless clarification is needed. "
        f"Scam category: {state.scam_category}. "
        f"Persona: {persona.display_name}, {persona.age_profile}. "
        f"Style: {persona.style_rules} "
        f"Goal bias: {persona.goal_bias} "
        f"Context channel={channel}, locale={locale}, language={language}. "
        f"Internal tactic: {tactical_hint}"
    )


def build_llm_messages(state: SessionState, metadata: Optional[Metadata], max_history: int) -> List[Dict[str, str]]:
    persona = next((p for p in PERSONAS if p.id == state.persona_id), PERSONAS[0])
    missing = missing_intel_targets(state)
    messages: List[Dict[str, str]] = [
        {
            "role": "system",
            "content": _system_prompt(persona, metadata, state, build_tactical_hint(missing)),
        }
    ]

    for msg in state.transcript[-max_history:]:
        role = "user" if msg.sender == "scammer" else "assistant"
        messages.append({"role": role, "content": msg.text})

    return messages


def _last_agent_reply(state: SessionState) -> str:
    for entry in reversed(state.transcript):
        if entry.sender == "user":
            return entry.text.strip()
    return ""


def _recent_agent_replies(state: SessionState, limit: int = 6) -> List[str]:
    replies: List[str] = []
    for entry in reversed(state.transcript):
        if entry.sender == "user":
            replies.append(entry.text.strip())
            if len(replies) >= limit:
                break
    return replies


def _latest_scammer_text(state: SessionState) -> str:
    for entry in reversed(state.transcript):
        if entry.sender == "scammer":
            return entry.text.lower()
    return ""


def _pick_non_repeating(
    candidates: List[str],
    last_reply: str,
    recent_replies: Optional[List[str]] = None,
    seed_hint: str = "",
) -> str:
    if not candidates:
        return "Please resend the details once more."

    blocked = set(recent_replies or [])
    filtered = [candidate for candidate in candidates if candidate not in blocked]
    if not filtered:
        filtered = [candidate for candidate in candidates if candidate != last_reply]
    if not filtered:
        filtered = candidates

    seed_value = f"{seed_hint}|{len(filtered)}"
    index = int(hashlib.sha256(seed_value.encode("utf-8")).hexdigest()[:8], 16) % len(filtered)
    return filtered[index]


def _persona_style_snippet(state: SessionState) -> str:
    if state.persona_id == "retired_teacher":
        return "I get mixed up with these steps"
    if state.persona_id == "busy_shop_owner":
        return "I am between customers right now"
    if state.persona_id == "overworked_employee":
        return "I am in a meeting right now"
    return "I want to do this safely"


def _human_fallback_candidates(state: SessionState) -> List[str]:
    style = _persona_style_snippet(state)
    scammer_text = _latest_scammer_text(state)

    candidates = [
        f"{style}. Please give me the exact steps once in short points.",
        "I can do this in 2 minutes. Confirm the official reference ID first.",
        "I do not want mistakes. Please repeat the account/UPI details carefully once more.",
        "The app is lagging on my side. Keep the request active and resend the details.",
        "I am trying now. Can you confirm the exact beneficiary name linked to that payment ID?",
        "Before I continue, share your official support number and reference one more time.",
        "I am almost done, but the page refreshed. Please send the same instructions again.",
        "Please wait, I am switching networks. Send the exact details again so I can proceed.",
        "I can proceed now. Tell me the exact sequence so I do not miss anything.",
        "I am opening the app now. Please hold and resend the key details once.",
    ]

    if "otp" in scammer_text:
        candidates.extend(
            [
                "No OTP has arrived yet. Should I wait or request a fresh one?",
                "OTP is delayed on this SIM. Can you keep this request open for a minute?",
                "I got a code but I am not sure if it is the right OTP. Please confirm what I should check first.",
            ]
        )
    if "reference" in scammer_text or "ref" in scammer_text:
        candidates.extend(
            [
                "Noted. Please repeat the reference ID slowly once more.",
                "Can you send the reference ID and helpline in one message?",
            ]
        )
    if "http" in scammer_text or "link" in scammer_text:
        candidates.extend(
            [
                "The link keeps redirecting. Please send the full URL again.",
                "I tapped it, but it did not open properly. Resend the link once.",
            ]
        )
    if "upi" in scammer_text or "@" in scammer_text:
        candidates.extend(
            [
                "I have two UPI apps. Which one should I use and what exact ID should I enter?",
                "Please confirm the UPI handle with exact spelling and amount before I pay.",
            ]
        )

    return candidates


def generate_rule_based_reply(state: SessionState) -> str:
    missing = missing_intel_targets(state)
    last_reply = _last_agent_reply(state)
    recent_replies = _recent_agent_replies(state, limit=6)
    seed_base = f"{state.session_id}:{state.agent_turns}"

    if state.agent_turns == 0:
        return (
            "Hi, I just saw your message. Which bank is this about? "
            "Please share the official helpline or reference number so I can verify."
        )

    if state.agent_turns == 1:
        if "link" in missing:
            return _pick_non_repeating(
                [
                    "Can you send the verification link again? It is not opening on my phone.",
                    "Please resend the link once more. It failed to load for me.",
                ],
                last_reply,
                recent_replies=recent_replies,
                seed_hint=f"{seed_base}:early-link",
            )
        if "upi" in missing:
            return _pick_non_repeating(
                [
                    "My UPI app is not showing any request. What UPI ID should I use?",
                    "I can pay now. Please share your exact UPI handle again.",
                ],
                last_reply,
                recent_replies=recent_replies,
                seed_hint=f"{seed_base}:early-upi",
            )
        return "Could you repeat the exact steps once? I do not want to make a mistake."

    if state.agent_turns == 2:
        if "phone" in missing:
            return _pick_non_repeating(
                [
                    "Is there a number I can call back? My connection keeps dropping.",
                    "Please share a callback number. The line keeps disconnecting.",
                ],
                last_reply,
                recent_replies=recent_replies,
                seed_hint=f"{seed_base}:mid-phone",
            )
        if "account" in missing:
            return _pick_non_repeating(
                [
                    "Before I proceed, can you confirm the account number or IFSC for verification?",
                    "Share the account number or IFSC once so I can complete this safely.",
                ],
                last_reply,
                recent_replies=recent_replies,
                seed_hint=f"{seed_base}:mid-account",
            )
        return "I am about to proceed, but I am at work. Please resend the details."

    if "upi" in missing:
        return _pick_non_repeating(
            [
                "I am ready now. Please send the UPI ID and the exact amount again.",
                "Please confirm the UPI ID once more with the amount so I can transfer now.",
                "I can do it now. Share the UPI handle and amount one last time.",
                "My app asks for beneficiary name too. Please send UPI ID, name, and amount together.",
                "Before I pay, confirm the UPI handle with exact spelling and amount once.",
                "I am on the payment screen now. Please resend the UPI details exactly.",
            ],
            last_reply,
            recent_replies=recent_replies,
            seed_hint=f"{seed_base}:late-upi",
        )

    if "link" in missing:
        return _pick_non_repeating(
            [
                "I still cannot open the link. Please send it again or the official site.",
                "The link still fails for me. Please resend it carefully.",
                "The page timed out here. Can you share the same link again?",
                "Please send the full link again without shortening it.",
            ],
            last_reply,
            recent_replies=recent_replies,
            seed_hint=f"{seed_base}:late-link",
        )

    if "phone" in missing:
        return _pick_non_repeating(
            [
                "Can you share a callback number? I do not want to miss any update.",
                "Please send a direct number so I can call immediately.",
                "I may miss messages now. Share a direct helpline number please.",
                "Send one reliable callback number and reference so I can confirm quickly.",
            ],
            last_reply,
            recent_replies=recent_replies,
            seed_hint=f"{seed_base}:late-phone",
        )

    return _pick_non_repeating(
        _human_fallback_candidates(state),
        last_reply,
        recent_replies=recent_replies,
        seed_hint=f"{seed_base}:human-fallback",
    )


def generate_agent_reply(
    state: SessionState,
    metadata: Optional[Metadata],
    openai: Optional[OpenAIClient],
    gemini: Optional[GeminiClient],
    max_history: int,
) -> Tuple[str, str]:
    messages = build_llm_messages(state, metadata, max_history=max_history)

    if openai and openai.api_key:
        raw = openai.chat(messages, temperature=0.7, max_tokens=120)
        reply = sanitize_reply(raw)
        if reply:
            return reply, "openai"

    if gemini and gemini.api_key:
        raw = gemini.chat(messages, temperature=0.7, max_tokens=120)
        reply = sanitize_reply(raw)
        if reply:
            return reply, "gemini"

    return generate_rule_based_reply(state), "rules"

