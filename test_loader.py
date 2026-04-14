# test_loader.py
from src.parser.pcap_loader           import load_pcap, save_parsed
from src.correlation.session_builder  import build_sessions, save_sessions
from src.features.feature_engineer    import (build_feature_dataframe,
                                               save_features)
from src.rules.rca_rules              import label_sessions
from rich.console import Console
from rich.table   import Table
import json

PCAP = "data/raw_pcaps/Trace-05.pcap"
console = Console()

# ── Phase 1: Parse ─────────────────────────────────────────────
results  = load_pcap(PCAP)
save_parsed(results)

# ── Phase 2: Correlate ─────────────────────────────────────────
sessions = build_sessions(results)

# ── Phase 3a: Apply RCA rules (auto-labeling) ──────────────────
sessions = label_sessions(sessions)
save_sessions(sessions)

# ── Phase 3b: Extract features ─────────────────────────────────
df = build_feature_dataframe(sessions)

# Add RCA label to dataframe
df["rca_label"] = [s["rca"]["rca_label"] for s in sessions]
save_features(df)

# ── Display results ────────────────────────────────────────────
console.rule("[bold cyan]RCA Results — Phase 3[/bold cyan]")

table = Table(show_header=True, header_style="bold")
table.add_column("Call-ID",      width=24)
table.add_column("Flow",         width=34)
table.add_column("Final",        width=6)
table.add_column("RCA Label",    width=24)
table.add_column("Conf%",        width=6)
table.add_column("Evidence",     width=42)

COLORS = {
    "NORMAL_CALL":           "green",
    "USER_ABORT":            "yellow",
    "NO_ANSWER_TIMEOUT":     "red",
    "SERVICE_TIMEOUT":       "red",
    "SUBSCRIBER_UNREACHABLE":"red",
    "USER_BUSY":             "yellow",
    "CODEC_MISMATCH":        "magenta",
    "CHARGING_FAILURE":      "red",
    "ROUTING_FAILURE":       "red",
    "CALL_FORWARDED":        "cyan",
    "ANNOUNCEMENT":          "cyan",
    "SERVER_ERROR":          "red",
    "UNKNOWN":               "dim",
}

for s in sessions:
    rca    = s.get("rca", {})
    label  = rca.get("rca_label", "?")
    color  = COLORS.get(label, "white")
    final  = s.get("final_sip_code") or "—"
    ev     = rca.get("evidence", [])
    ev_str = " | ".join(ev[:2])[:40]
    cid    = str(s["call_id"])[:22] + ".."

    table.add_row(
        cid,
        str(s.get("flow",""))[:32],
        final,
        f"[{color}]{label}[/{color}]",
        str(rca.get("confidence_pct","?")),
        ev_str,
    )

console.print(table)

console.print(f"\n[bold]Feature matrix:[/bold] "
              f"{df.shape[0]} rows × {df.shape[1]} columns")
console.print(f"[bold]Features saved:[/bold] data/features/features.csv")
console.print(f"\n[bold green]✅ Phases 1-3 complete![/bold green]")
console.print("[dim]Next: Phase 4 — ML Training (XGBoost)[/dim]")
