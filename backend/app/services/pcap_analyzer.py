import pyshark
import nest_asyncio
import asyncio
from sqlalchemy.orm import Session
from ..db import models
from datetime import datetime

from ..db.database import SessionLocal

class PCAPAnalyzer:
    def __init__(self, file_path: str, capture_id: int):
        self.file_path = file_path
        self.capture_id = capture_id
        self.db = SessionLocal()
        
    def analyze(self):
        nest_asyncio.apply()
        try:
            capture = self.db.query(models.Capture).filter(models.Capture.id == self.capture_id).first()
            if not capture:
                return

            cap = pyshark.FileCapture(self.file_path, keep_packets=False)
            
            total_packets = 0
            total_bytes = 0
            protocols = {}
            syn_count = {}
            icmp_count = {}
            udp_count = {}
            cleartext_usage = set()
            devices = {}
            
            for pkt in cap:
                total_packets += 1
                try:
                    length = int(pkt.length)
                except:
                    length = 0
                    
                total_bytes += length
                highest_layer = pkt.highest_layer
                protocols[highest_layer] = protocols.get(highest_layer, 0) + 1
                
                src_ip = None
                dst_ip = None
                src_port = None
                dst_port = None
                
                if hasattr(pkt, 'ip'):
                    src_ip = pkt.ip.src
                    dst_ip = pkt.ip.dst
                    devices[src_ip] = devices.get(src_ip, 0) + 1
                    devices[dst_ip] = devices.get(dst_ip, 0) + 1
                elif hasattr(pkt, 'ipv6'):
                    src_ip = pkt.ipv6.src
                    dst_ip = pkt.ipv6.dst
                    devices[src_ip] = devices.get(src_ip, 0) + 1
                    devices[dst_ip] = devices.get(dst_ip, 0) + 1
                    
                if hasattr(pkt, 'tcp'):
                    try:
                        src_port = int(pkt.tcp.srcport)
                        dst_port = int(pkt.tcp.dstport)
                        flags_syn = str(pkt.tcp.flags_syn)
                        flags_ack = str(pkt.tcp.flags_ack)
                        if flags_syn in ['1', 'True', 'true'] and flags_ack in ['0', 'False', 'false'] and src_ip:
                            syn_count[src_ip] = syn_count.get(src_ip, 0) + 1
                    except:
                        pass
                elif hasattr(pkt, 'udp'):
                    try:
                        src_port = int(pkt.udp.srcport)
                        dst_port = int(pkt.udp.dstport)
                        if src_ip:
                            udp_count[src_ip] = udp_count.get(src_ip, 0) + 1
                    except:
                        pass
                        
                if src_port in [21, 23] or dst_port in [21, 23]:
                    if src_ip:
                        cleartext_usage.add((src_ip, src_port if src_port in [21, 23] else dst_port))
                
                elif hasattr(pkt, 'icmp') or hasattr(pkt, 'icmpv6'):
                    if src_ip:
                        icmp_count[src_ip] = icmp_count.get(src_ip, 0) + 1
                        
                timestamp = float(pkt.sniff_timestamp) if hasattr(pkt, 'sniff_timestamp') else 0.0
                
                db_pkt = models.Packet(
                    capture_id=self.capture_id,
                    packet_number=total_packets,
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=highest_layer,
                    length=length,
                    summary=f"{src_ip or 'Any'} -> {dst_ip or 'Any'} [{highest_layer}] Len={length}"
                )
                self.db.add(db_pkt)
                
                if total_packets % 500 == 0:
                    self.db.commit()
                    
                if total_packets >= 10000: # Limit for MVP parsing speed
                    break
                    
            self.db.commit()
            
            # Save stats
            capture.total_packets = total_packets
            capture.total_bytes = total_bytes
            
            # Save devices
            for ip in devices.keys():
                dev = models.Device(capture_id=self.capture_id, ip_address=ip)
                self.db.add(dev)
                
            # Save protocols
            for proto, count in protocols.items():
                pstat = models.ProtocolStat(capture_id=self.capture_id, protocol_name=proto, packet_count=count, byte_count=0)
                self.db.add(pstat)
                
            # Threats
            threats = []
            for ip, count in syn_count.items():
                if count >= 20:
                    threats.append(models.Threat(
                        capture_id=self.capture_id,
                        severity="High",
                        category="Port Scan",
                        description="Possible Port Scan",
                        evidence=f"{ip} sent {count} SYN packets",
                        recommendation="Investigate source IP for unauthorized scanning activity."
                    ))
                    
            for ip, count in icmp_count.items():
                if count >= 20:
                    threats.append(models.Threat(
                        capture_id=self.capture_id,
                        severity="Medium",
                        category="ICMP Flood",
                        description="Possible ICMP Flood / Ping Flood",
                        evidence=f"{ip} sent {count} ICMP packets",
                        recommendation="Investigate source IP for DoS attack (Ping Flood)."
                    ))
                    
            for ip, count in udp_count.items():
                if count >= 100:
                    threats.append(models.Threat(
                        capture_id=self.capture_id,
                        severity="High",
                        category="UDP Flood",
                        description="Possible UDP Flood Attack",
                        evidence=f"{ip} sent {count} UDP packets",
                        recommendation="Investigate source IP for volumetric DDoS."
                    ))

            for ip, port in cleartext_usage:
                protocol_name = "FTP" if port == 21 else "Telnet"
                threats.append(models.Threat(
                    capture_id=self.capture_id,
                    severity="Critical",
                    category="Cleartext Protocol",
                    description=f"Insecure {protocol_name} Usage",
                    evidence=f"{ip} is communicating over unencrypted port {port}",
                    recommendation=f"Block {protocol_name} traffic and migrate to secure alternatives (SFTP/SSH)."
                ))
            
            for threat in threats:
                self.db.add(threat)
                
            capture.risk_score = min(100, len(threats) * 25)
            
            # --- Generate AI Summary ---
            summary_paragraphs = []
            mb_size = total_bytes / (1024 * 1024)
            
            # 1. Volume & Scope
            summary_paragraphs.append(f"This packet capture contains {total_packets:,} packets totaling {mb_size:.2f} MB of data. "
                                      f"The traffic involves {len(devices)} unique IP addresses or endpoints.")
            
            # 2. Protocol Breakdown
            sorted_protos = sorted(protocols.items(), key=lambda item: item[1], reverse=True)
            if sorted_protos:
                top_proto = sorted_protos[0][0]
                proto_names = [p[0] for p in sorted_protos[:3]]
                summary_paragraphs.append(f"The primary protocol observed is {top_proto}, which dominates the traffic. "
                                          f"Other significant protocols include {', '.join(proto_names[1:])}.")
                                          
            # 3. Security posture
            if len(threats) == 0:
                summary_paragraphs.append("No immediate security threats or anomalies were detected by the baseline heuristics. The traffic appears nominal.")
            else:
                summary_paragraphs.append(f"Security Analysis flagged {len(threats)} potential threat(s). "
                                          f"These include {', '.join(set([t.category for t in threats]))}. "
                                          "Immediate investigation of the flagged source IPs is highly recommended.")
            
            capture.ai_summary = " ".join(summary_paragraphs)
            capture.status = "completed"
            
            self.db.commit()
            cap.close()
            
        except Exception as e:
            print(f"Error parsing pcap: {e}")
            capture = self.db.query(models.Capture).filter(models.Capture.id == self.capture_id).first()
            if capture:
                capture.status = "failed"
                self.db.commit()
        finally:
            self.db.close()

def run_analysis(file_path: str, capture_id: int):
    analyzer = PCAPAnalyzer(file_path, capture_id)
    analyzer.analyze()
