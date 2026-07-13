from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, Text, JSON
from sqlalchemy.orm import relationship
from .database import Base
from datetime import datetime

class Capture(Base):
    __tablename__ = "captures"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    file_hash = Column(String, index=True, unique=True)
    size = Column(Integer)
    status = Column(String, default="processing")  # processing, completed, failed
    upload_time = Column(DateTime, default=datetime.utcnow)
    
    # Stats
    total_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    capture_duration = Column(Float, default=0.0)
    risk_score = Column(Integer, default=0)
    ai_summary = Column(Text, nullable=True)
    
    packets = relationship("Packet", back_populates="capture", cascade="all, delete")
    threats = relationship("Threat", back_populates="capture", cascade="all, delete")
    devices = relationship("Device", back_populates="capture", cascade="all, delete")
    protocols = relationship("ProtocolStat", back_populates="capture", cascade="all, delete")

class Packet(Base):
    __tablename__ = "packets"
    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(Integer, ForeignKey("captures.id"))
    packet_number = Column(Integer)
    timestamp = Column(Float)
    src_ip = Column(String, index=True, nullable=True)
    dst_ip = Column(String, index=True, nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String, index=True)
    length = Column(Integer)
    summary = Column(Text)
    
    capture = relationship("Capture", back_populates="packets")

class Threat(Base):
    __tablename__ = "threats"
    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(Integer, ForeignKey("captures.id"))
    severity = Column(String) # Critical, High, Medium, Low, Informational
    category = Column(String)
    description = Column(String)
    evidence = Column(Text)
    recommendation = Column(Text)
    
    capture = relationship("Capture", back_populates="threats")

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(Integer, ForeignKey("captures.id"))
    ip_address = Column(String, index=True)
    mac_address = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    
    capture = relationship("Capture", back_populates="devices")

class ProtocolStat(Base):
    __tablename__ = "protocol_stats"
    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(Integer, ForeignKey("captures.id"))
    protocol_name = Column(String)
    packet_count = Column(Integer)
    byte_count = Column(Integer)
    
    capture = relationship("Capture", back_populates="protocols")
