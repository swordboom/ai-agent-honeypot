from typing import List, Literal, Optional, Union

from pydantic import BaseModel, Field


class Message(BaseModel):
    sender: Literal["scammer", "user"]
    text: str
    timestamp: Optional[Union[int, str]] = None


class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class MessageEvent(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Optional[Metadata] = None

