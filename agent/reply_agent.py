import hashlib
from typing import Dict, List, Optional, Tuple

from agent.llm_clients import OpenRouterClient, sanitize_reply
from agent.multilingual import reply_language_instruction
from agent.personas import PERSONAS, Persona
from models.api import Metadata
from models.session import SessionState, TranscriptMessage
from services.strategy_state import STRATEGY_HARVEST_MODE, STRATEGY_SUSPICIOUS


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
        return "Ask where the verification page is and for the exact link, without implying they already sent one."
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
        "You are playing an ordinary person who received a suspicious message. "
        "Act cautious, a little confused, and keep the sender talking by asking short clarifying questions. "
        "Never reveal you are an AI or that you suspect fraud. Never provide harmful instructions or insult anyone. "
        "Keep every reply under 35 words. Write in first person as yourself, not as a narrator. "
        "Do not add labels, headings, or meta-commentary — just the reply text itself. "
        f"{reply_language_instruction(state.language)} "
        f"The sender is communicating in: {state.language_name}. "
        f"Apparent scheme type: {state.scam_category}. "
        f"Your character: {persona.display_name}, {persona.age_profile}. "
        f"Your speaking style: {persona.style_rules} "
        f"Your goal in this conversation: {persona.goal_bias} "
        f"Channel={channel}, locale={locale}. "
        f"Your next move: {tactical_hint}"
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


# Deterministic last-resort replies per language. The LLM handles normal traffic;
# these keep a vernacular session from suddenly answering in English when every free
# model is rate-limited, which would blow the persona instantly.
# ponytail: one line per intel target per language, not a template engine.
VERNACULAR_FALLBACKS: Dict[str, Dict[str, List[str]]] = {
    "hi": {
        "upi": [
            "मैं अभी भेज रहा हूँ। अपना UPI ID और रकम एक बार फिर से भेजिए।",
            "पेमेंट स्क्रीन खुली है। UPI ID सही स्पेलिंग के साथ दोबारा भेजें।",
        ],
        "link": [
            "लिंक मेरे फोन पर नहीं खुल रहा है। कृपया पूरा लिंक फिर से भेजिए।",
            "पेज लोड नहीं हुआ। वही लिंक एक बार और भेजें।",
        ],
        "phone": [
            "कॉल बार-बार कट रही है। एक कॉलबैक नंबर भेज दीजिए।",
            "मुझे किस नंबर पर कॉल करना है? हेल्पलाइन नंबर भेजिए।",
        ],
        "account": [
            "आगे बढ़ने से पहले खाता नंबर और IFSC एक बार कन्फर्म कर दीजिए।",
            "अकाउंट नंबर और IFSC भेजिए, मैं अभी ट्रांसफर करता हूँ।",
        ],
        "generic": [
            "मुझे थोड़ी उलझन हो रही है। कृपया पूरे स्टेप्स छोटे पॉइंट्स में एक बार भेजिए।",
            "नेटवर्क स्लो है। रेफरेंस नंबर और डिटेल्स एक साथ फिर से भेज दीजिए।",
        ],
        "probe": [
            "यह किस बारे में है? अपना ऑफिशियल हेल्पलाइन नंबर और केस रेफरेंस भेजिए।",
            "मुझे समझ नहीं आया। कृपया अपनी ऑफिशियल डिटेल्स के साथ फिर से समझाइए।",
        ],
    },
    "bn": {
        "upi": ["আমি এখনই পাঠাচ্ছি। আপনার UPI আইডি আর টাকার অঙ্ক আবার পাঠান।"],
        "link": ["লিঙ্কটা আমার ফোনে খুলছে না। পুরো লিঙ্কটা আবার পাঠান।"],
        "phone": ["লাইন বারবার কেটে যাচ্ছে। একটা কলব্যাক নম্বর পাঠান।"],
        "account": ["এগোনোর আগে অ্যাকাউন্ট নম্বর আর IFSC একবার নিশ্চিত করুন।"],
        "generic": ["একটু গুলিয়ে যাচ্ছে। ধাপগুলো ছোট পয়েন্টে আরেকবার পাঠান।"],
        "probe": ["এটা কী নিয়ে? আপনার অফিসিয়াল হেল্পলাইন আর কেস রেফারেন্স পাঠান।"],
    },
    "ta": {
        "upi": ["இப்போது அனுப்புகிறேன். உங்கள் UPI ஐடி மற்றும் தொகையை மீண்டும் அனுப்புங்கள்."],
        "link": ["இணைப்பு என் ஃபோனில் திறக்கவில்லை. முழு இணைப்பையும் மீண்டும் அனுப்புங்கள்."],
        "phone": ["அழைப்பு துண்டிக்கப்படுகிறது. ஒரு தொடர்பு எண் அனுப்புங்கள்."],
        "account": ["தொடர்வதற்கு முன் கணக்கு எண் மற்றும் IFSC ஐ உறுதிப்படுத்துங்கள்."],
        "generic": ["எனக்கு குழப்பமாக உள்ளது. படிகளை சிறு புள்ளிகளாக மீண்டும் அனுப்புங்கள்."],
        "probe": ["இது எதைப் பற்றியது? உங்கள் அதிகாரப்பூர்வ எண் மற்றும் வழக்கு குறிப்பை அனுப்புங்கள்."],
    },
    "te": {
        "upi": ["ఇప్పుడే పంపుతున్నాను. మీ UPI ఐడీ మరియు మొత్తాన్ని మళ్లీ పంపండి."],
        "link": ["లింక్ నా ఫోన్‌లో తెరవడం లేదు. పూర్తి లింక్ మళ్లీ పంపండి."],
        "phone": ["కాల్ కట్ అవుతోంది. ఒక కాల్‌బ్యాక్ నంబర్ పంపండి."],
        "account": ["ముందుకు వెళ్లే ముందు ఖాతా నంబర్ మరియు IFSC నిర్ధారించండి."],
        "generic": ["నాకు కొంచెం గందరగోళంగా ఉంది. దశలను చిన్న పాయింట్లుగా మళ్లీ పంపండి."],
        "probe": ["ఇది దేని గురించి? మీ అధికారిక హెల్ప్‌లైన్ మరియు కేసు రిఫరెన్స్ పంపండి."],
    },
    "mr": {
        "upi": ["मी आत्ताच पाठवतो. तुमचा UPI आयडी आणि रक्कम पुन्हा पाठवा."],
        "link": ["लिंक माझ्या फोनवर उघडत नाही. पूर्ण लिंक पुन्हा पाठवा."],
        "phone": ["कॉल सतत कट होतोय. एक कॉलबॅक नंबर पाठवा."],
        "account": ["पुढे जाण्यापूर्वी खाते क्रमांक आणि IFSC एकदा निश्चित करा."],
        "generic": ["मला थोडा गोंधळ होतोय. सर्व स्टेप्स छोट्या पॉइंट्समध्ये पुन्हा पाठवा."],
        "probe": ["हे कशाबद्दल आहे? तुमचा अधिकृत हेल्पलाइन नंबर आणि केस रेफरन्स पाठवा."],
    },
}


def _vernacular_reply(state: SessionState, bucket: str, missing: List[str]) -> Optional[str]:
    lists = VERNACULAR_FALLBACKS.get(state.language)
    if not lists:
        return None

    key = bucket
    if bucket == "target":
        key = next((t for t in ("upi", "link", "phone", "account") if t in missing), "generic")

    candidates = lists.get(key) or lists["generic"]
    return _pick_non_repeating(
        candidates,
        _last_agent_reply(state),
        recent_replies=_recent_agent_replies(state, limit=6),
        seed_hint=f"{state.session_id}:{state.agent_turns}:{key}",
    )


# The first reply is the one that has to land. Asking "which bank is this about?"
# about a parcel seizure or a lottery win is an instant tell, so the opener follows the
# category the detector just assigned. Every line still fishes for a reference number.
_OPENING_LINES = {
    "BANK_FRAUD": "Hi, I just saw your message. Which bank is this about? "
                  "Please share the official helpline or reference number so I can verify.",
    "KYC_FRAUD": "Hi, I just saw this. Which bank is my KYC pending with? "
                 "Please send the official reference number so I can check.",
    # Payment-neutral: a UPI demand can be a fake bank, a fake job fee or a fake fine.
    "UPI_FRAUD": "Hi, I just saw this. Who exactly is this payment going to? "
                 "Please share the official reference number before I send anything.",
    "LOTTERY_SCAM": "I do not remember entering any lottery. Which company is this, "
                    "and what is the official reference number?",
    "DIGITAL_ARREST": "I have not done anything wrong. Which department is this? "
                      "Please give me an official case number I can check.",
    "REFUND_SCAM": "Which order or payment is this refund for? "
                   "Please share the reference number so I can confirm.",
    "CRYPTO_SCAM": "I have never invested in anything like this. Which company are you from? "
                   "Please share official details.",
    "PHISHING": "Sorry, who is this from? Please share an official reference number "
                "so I can check before I open anything.",
}

_DEFAULT_OPENING = ("Sorry, who is this? Please share an official reference number "
                    "so I can verify before I do anything.")


def _opening_line(category: str) -> str:
    return _OPENING_LINES.get(category, _DEFAULT_OPENING)


def generate_rule_based_reply(state: SessionState) -> str:
    missing = missing_intel_targets(state)

    vernacular = _vernacular_reply(state, "target", missing)
    if vernacular:
        return vernacular

    last_reply = _last_agent_reply(state)
    recent_replies = _recent_agent_replies(state, limit=6)
    seed_base = f"{state.session_id}:{state.agent_turns}"

    if state.strategy_state == STRATEGY_HARVEST_MODE:
        return _pick_non_repeating(
            [
                "I am trying now. Please share callback number, reference ID, and exact payment details in one message.",
                "Before I proceed, send supervisor name, reference ID, and the exact account or UPI details again.",
                "Network is unstable. Please send the payment ID, helpline, and reference together so I can complete quickly.",
            ],
            last_reply,
            recent_replies=recent_replies,
            seed_hint=f"{seed_base}:harvest",
        )

    if state.agent_turns == 0:
        return _opening_line(state.scam_category)

    if state.agent_turns == 1:
        if "link" in missing:
            return _pick_non_repeating(
                [
                    "Where exactly do I need to verify? Is there an official link or website?",
                    "How do I do this verification? Please send the exact page I should open.",
                ],
                last_reply,
                recent_replies=recent_replies,
                seed_hint=f"{seed_base}:early-link",
            )
        if "upi" in missing:
            return _pick_non_repeating(
                [
                    "My UPI app is open but I see no request. What UPI ID should I send it to?",
                    "I can pay now. What is your exact UPI handle?",
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
                "I am ready now. What is the UPI ID and the exact amount?",
                "Tell me the UPI ID with the amount so I can transfer now.",
                "I can do it now. Which UPI handle and how much?",
                "My app asks for beneficiary name too. Please send UPI ID, name, and amount together.",
                "Before I pay, give me the UPI handle with exact spelling and the amount.",
                "I am on the payment screen now. What UPI details do I enter?",
            ],
            last_reply,
            recent_replies=recent_replies,
            seed_hint=f"{seed_base}:late-upi",
        )

    if "link" in missing:
        return _pick_non_repeating(
            [
                "Is there an official link for this? I cannot find the page.",
                "Which site should I open? Please send the full web address.",
                "I do not see any link in your messages. Where do I complete this?",
                "Please send the complete link, not a shortened one.",
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


def generate_probe_reply(state: SessionState) -> str:
    vernacular = _vernacular_reply(state, "probe", [])
    if vernacular:
        return vernacular

    last_reply = _last_agent_reply(state)
    recent_replies = _recent_agent_replies(state, limit=6)
    seed_base = f"{state.session_id}:{state.scammer_messages}:{state.strategy_state}"

    if state.strategy_state == STRATEGY_SUSPICIOUS:
        return _pick_non_repeating(
            [
                "Can you share your official support number and case reference so I can confirm first?",
                "Please send the official website and complaint ID before I continue.",
                "I need to verify with my bank first. Can you share your employee ID and helpline?",
            ],
            last_reply,
            recent_replies=recent_replies,
            seed_hint=f"{seed_base}:suspicious-probe",
        )

    return _pick_non_repeating(
        [
            "Sorry, I am not sure I understand. Can you clarify what this is about?",
            "Can you explain this once more with your official details?",
        ],
        last_reply,
        recent_replies=recent_replies,
        seed_hint=f"{seed_base}:neutral-probe",
    )


def generate_agent_reply(
    state: SessionState,
    metadata: Optional[Metadata],
    llm: Optional[OpenRouterClient],
    max_history: int,
) -> Tuple[str, str]:
    """
    OpenRouter free models generate the reply. `generate_rule_based_reply` is the
    terminal safety net for when every free model is rate-limited - without it a
    throttled session would return no reply at all and the engagement would die.
    """
    messages = build_llm_messages(state, metadata, max_history=max_history)

    if llm and llm.api_key:
        raw = llm.chat(messages, temperature=0.7, max_tokens=120)
        reply = sanitize_reply(raw)
        if reply:
            return reply, "openrouter"

    return generate_rule_based_reply(state), "rules"
