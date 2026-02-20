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


class DashboardSummary(BaseModel):
    activeEngagements: int
    totalSessions: int
    finalizedSessions: int
    totalScammerTimeWastedSeconds: int
    totalExtracted: DashboardIntelCounts


class DashboardSessionCard(BaseModel):
    sessionId: str
    persona: str
    scamDetected: bool
    scamCategory: str
    scamConfidence: float
    rollingScamScore: float = 0.0
    strategyState: str = "Neutral"
    engagementComplete: bool
    replyProvider: str = "rules"
    messageCount: int
    lastUpdated: int
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
    scamDetected: bool
    scamCategory: str
    scamConfidence: float
    rollingScamScore: float
    strategyState: str
    scamTriggers: List[str]
    engagementComplete: bool
    replyProvider: str
    callbackSent: bool
    callbackAttempts: int
    callbackLastStatus: Optional[int]
    callbackLastError: Optional[str]
    totalMessages: int
    timeWastedSeconds: int
    finalOutput: Dict[str, object]
    extractedIntelligence: Dict[str, List[str]]
    extendedIntelligence: Dict[str, List[str]]
    transcript: List[DashboardTranscriptEntry]


class DashboardMapPoint(BaseModel):
    countryCode: str
    countryName: str
    count: int
