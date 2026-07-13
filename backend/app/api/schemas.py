from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List


class CaptureBase(BaseModel):
    id: int
    filename: str
    file_hash: str
    size: int
    status: str
    upload_time: datetime
    total_packets: int
    total_bytes: int
    capture_duration: float
    risk_score: int
    ai_summary: Optional[str] = None

    model_config = {"from_attributes": True}


class ProtocolStatSchema(BaseModel):
    id: int
    capture_id: int
    protocol_name: str
    packet_count: int
    byte_count: int

    model_config = {"from_attributes": True}


class PacketSchema(BaseModel):
    id: int
    capture_id: int
    packet_number: int
    timestamp: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    summary: Optional[str]

    model_config = {"from_attributes": True}


class ThreatSchema(BaseModel):
    id: int
    capture_id: int
    severity: str
    category: str
    description: str
    evidence: Optional[str]
    recommendation: Optional[str]

    model_config = {"from_attributes": True}


class DeviceSchema(BaseModel):
    id: int
    capture_id: int
    ip_address: str
    mac_address: Optional[str]
    hostname: Optional[str]
    vendor: Optional[str]

    model_config = {"from_attributes": True}


class CaptureDetailSchema(BaseModel):
    capture: CaptureBase
    protocols: List[ProtocolStatSchema]

    model_config = {"from_attributes": True}


class PacketListSchema(BaseModel):
    total: int
    packets: List[PacketSchema]
