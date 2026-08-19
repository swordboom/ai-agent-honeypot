from typing import Dict, List, Optional, Union

from pydantic import BaseModel


class DashboardIntelCounts(BaseModel):
    bankAccounts: int
    upiIds: int
    phishingLinks: int
    phoneNumbers: int
    emailAddresses: int = 0
    caseIds: int = 0
    policyNumbers: int = 0
    orderNumbers: int = 0
    referenceIds: int = 0
    amounts: int = 0
    emails: int = 0
    cryptoWallets: int = 0
    domains: int = 0
    ipAddresses: int = 0
    usernames: int = 0


class DashboardCountEntry(BaseModel):
    """Generic label/value pair backing the category, language and severity charts."""

    label: str
    value: int


class DashboardTimelinePoint(BaseModel):
    bucketStart: int
    sessions: int
    messages: int


class DashboardSummary(BaseModel):
    activeEngagements: int
    totalSessions: int
    finalizedSessions: int
    scamSessions: int
    totalScammerTimeWastedSeconds: int
    totalMessages: int
    totalExtracted: DashboardIntelCounts
    severityCounts: Dict[str, int] = {}
    openIncidents: int = 0
    topSeverity: str = "LOW"
    triageFunnel: Dict[str, object] = {}
    categoryBreakdown: List[DashboardCountEntry] = []
    languageBreakdown: List[DashboardCountEntry] = []
    providerBreakdown: List[DashboardCountEntry] = []
    timeline: List[DashboardTimelinePoint] = []
    llmModelHealth: Dict[str, object] = {}


class DashboardSessionCard(BaseModel):
    sessionId: str
    persona: str
    sourceType: str = "honeypot"
    scamDetected: bool
    scamCategory: str
    scamConfidence: float
    rollingScamScore: float = 0.0
    strategyState: str = "Neutral"
    engagementComplete: bool
    replyProvider: str = "rules"
    messageCount: int
    lastUpdated: int
    language: str = "en"
    languageName: str = "English"
    incidentId: Optional[str] = None
    incidentSeverity: Optional[str] = None
    intelCounts: DashboardIntelCounts


class DashboardTranscriptEntry(BaseModel):
    sender: str
    text: str
    timestamp: Union[int, str]
    provider: Optional[str] = None


class DashboardSessionDetail(BaseModel):
    sessionId: str
    personaId: str
    persona: str
    sourceType: str = "honeypot"
    scamDetected: bool
    scamCategory: str
    scamConfidence: float
    rollingScamScore: float
    strategyState: str
    scamTriggers: List[str]
    engagementComplete: bool
    replyProvider: str
    totalMessages: int
    timeWastedSeconds: int
    language: str = "en"
    languageName: str = "English"
    languageConfidence: float = 0.0
    languagesSeen: List[str] = []
    vernacularScore: float = 0.0
    incidentId: Optional[str] = None
    incidentName: Optional[str] = None
    incidentSeverity: Optional[str] = None
    incidentTriage: Optional[str] = None
    responsePlan: List[Dict[str, object]] = []
    report: Dict[str, object]
    extractedIntelligence: Dict[str, List[str]]
    extendedIntelligence: Dict[str, List[str]]
    transcript: List[DashboardTranscriptEntry]


class DashboardIncident(BaseModel):
    incidentId: str
    name: str
    severity: str
    severityScore: float
    sourceType: str = "Honeypot"
    scamCategory: str
    sessionIds: List[str]
    sessionCount: int
    firstSeen: int
    lastSeen: int
    durationSeconds: int
    sessionsPerMinute: float
    sharedIndicators: List[str]
    languages: List[str]
    totalMessages: int
    maxConfidence: float
    scoreBreakdown: Dict[str, float]
    recommendedAction: str
    triage: str = "ACTION_REQUIRED"
    responsePlan: List[Dict[str, object]] = []


class DashboardMapPoint(BaseModel):
    countryCode: str
    countryName: str
    count: int
