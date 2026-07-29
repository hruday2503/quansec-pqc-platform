from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class TunnelOut(BaseModel):
    id:             int
    name:           str
    local_host:     str
    local_id:       Optional[str]
    remote_host:    str
    remote_id:      Optional[str]
    state:          str
    ike_version:    int
    ike_proposal:   Optional[str]
    esp_proposal:   Optional[str]
    pqc_kem:        Optional[str]
    pqc_enabled:    bool
    bytes_in:       int
    bytes_out:      int
    packets_in:     int
    packets_out:    int
    established_at: Optional[datetime]
    last_seen:      datetime
    created_at:     datetime


class TunnelCreate(BaseModel):
    """Used to manually seed a tunnel config (before StrongSwan is up)."""
    name:        str
    local_host:  str
    remote_host: str
    ike_version: int = 2
    pqc_kem:     Optional[str] = "kyber1024"


class IPsecStats(BaseModel):
    total_tunnels: int
    established:   int
    down:          int
    pqc_enabled:   int
    pqc_coverage:  float       # 0.0–100.0
    total_bytes_in:  int
    total_bytes_out: int
    last_updated:  datetime


class IPsecEvent(BaseModel):
    id:          int
    tunnel_name: str
    event_type:  str
    detail:      Optional[dict]
    occurred_at: datetime
