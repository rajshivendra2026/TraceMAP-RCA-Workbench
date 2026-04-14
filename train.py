# train.py
"""
Training entry point — run this to train the XGBoost RCA model.

Usage:
    python train.py

What it does:
    1. Processes all PCAPs in data/raw_pcaps/ via the pipeline
    2. Generates synthetic training data for all RCA classes
    3. Combines real + synthetic into one labeled dataset
    4. Trains XGBoost with group-aware evaluation
    5. Saves model + encoder + metadata to data/models/

All hyperparameters and paths come from config.yaml.
"""

import sys
from pathlib import Path

from loguru import logger
from rich.console import Console
from rich.table import Table

# ── Ensure project root on path ───────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from src.config import cfg, cfg_path
from src.pipeline import build_training_dataframe, get_label_distribution
from src.ml.synthetic import generate_synthetic_dataset
from src.ml.train import train
from src.features.feature_engineer import ML_FEATURE_COLS

console = Console()


def main() -> None:
    console.rule("[bold cyan]Telecom RCA — Model Training[/bold cyan]")

    # ── Step 1: Process real PCAPs ────────────────────────────
    console.print("\n[bold]Step 1[/bold] Processing real PCAPs...")
    real_df = build_training_dataframe()

    if not real_df.empty:
        console.print(
            f"  Real sessions: [cyan]{len(real_df)}[/cyan] rows "
            f"from [cyan]{real_df['pcap_source'].nunique()}[/cyan] PCAP source(s)"
        )
        dist = get_label_distribution(real_df)
        console.print("  Label distribution:")
        for label, count in dist.items():
            console.print(f"    {label:<32}: {count}")
    else:
        console.print(
            "  [yellow]No sessions from real PCAPs — "
            "using synthetic data only.[/yellow]"
        )
        console.print(
            "  [dim]Add .pcap files to data/raw_pcaps/ "
            "for real training data.[/dim]"
        )

    # ── Step 2: Generate synthetic data ───────────────────────
    console.print("\n[bold]Step 2[/bold] Generating synthetic training data...")
    df = generate_synthetic_dataset(
        n_per_class=cfg("training.synthetic_per_class", 80),
        real_df=real_df if not real_df.empty else None,
    )

    console.print(
        f"  Combined dataset: [cyan]{len(df)}[/cyan] rows, "
        f"[cyan]{df['rca_label'].nunique()}[/cyan] classes"
    )

    # Ensure pcap_source column exists (synthetic rows have it set to "synthetic")
    if "pcap_source" not in df.columns:
        df["pcap_source"] = "synthetic"

    # Save the training dataset
    import os
    features_dir = cfg_path("data.features", "data/features")
    os.makedirs(features_dir, exist_ok=True)
    training_csv = f"{features_dir}/training_data.csv"
    df.to_csv(training_csv, index=False)
    console.print(f"  Training data saved → [dim]{training_csv}[/dim]")

    # ── Step 3: Train ─────────────────────────────────────────
    console.print("\n[bold]Step 3[/bold] Training XGBoost...")
    results = train(df)

    # ── Step 4: Results table ─────────────────────────────────
    console.rule("[bold green]Training Complete[/bold green]")

    table = Table(show_header=True, header_style="bold")
    table.add_column("RCA Class",   width=28)
    table.add_column("Precision",   width=10)
    table.add_column("Recall",      width=10)
    table.add_column("F1",          width=10)
    table.add_column("Support",     width=10)

    report = results["report"]
    for cls in results["classes"]:
        m   = report.get(cls, {})
        p   = m.get("precision", 0)
        r   = m.get("recall",    0)
        f1  = m.get("f1-score",  0)
        n   = int(m.get("support", 0))
        if n == 0:
            continue
        col = (
            "green"  if f1 > 0.85 else
            "yellow" if f1 > 0.65 else
            "red"
        )
        table.add_row(
            cls,
            f"[{col}]{p:.2f}[/{col}]",
            f"[{col}]{r:.2f}[/{col}]",
            f"[{col}]{f1:.2f}[/{col}]",
            str(n),
        )

    console.print(table)

    acc = results["accuracy"]
    cv  = results["cv_scores"]
    console.print(
        f"\n[bold]Test accuracy :[/bold] "
        f"[green]{acc:.1%}[/green]"
    )
    console.print(
        f"[bold]Cross-val     :[/bold] "
        f"[green]{cv.mean():.1%} ± {cv.std():.1%}[/green]"
    )

    model_path = cfg_path("model.path", "data/models/rca_model.pkl")
    console.print(
        f"\n[bold green]Model saved → {model_path}[/bold green]"
    )
    console.print(
        "[dim]Run the backend: python main.py[/dim]"
    )


if __name__ == "__main__":
    main()
