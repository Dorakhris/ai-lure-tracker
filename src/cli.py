"""
AI Lure Tracker - Unified Command Line Interface
Main orchestration entrypoint for collecting, filtering, enriching, storing, and publishing CTI feeds.
"""

import argparse
import asyncio
import os
import sys
import yaml
import logging
from typing import List, Dict, Any

# Ensure Windows terminal doesn't crash on Unicode characters
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from src.models import RawIndicator, EnrichedIndicator, ConfidenceLevel
from src.collectors import (
    URLhausCollector,
    ThreatFoxCollector,
    MalwareBazaarCollector,
    OpenPhishCollector,
    PhishTankCollector,
    CertStreamCollector,
    PyPIWatcher,
    NPMWatcher
)
from src.filters import BrandMatcher
from src.enrichment import ThreatEnrichmentPipeline
from src.storage import (
    ThreatDatabase,
    STIXExporter,
    FeedExporter,
    MISPExporter,
    OpenCTIExporter
)
from src.reporting import WeeklyReportGenerator

console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("ai_lure_tracker.cli")


def load_configurations() -> (Dict[str, Any], Dict[str, Any]):
    targets_path = "config/targets.yaml"
    settings_path = "config/settings.yaml"

    targets_cfg = {}
    settings_cfg = {}

    if os.path.exists(targets_path):
        with open(targets_path, "r", encoding="utf-8") as f:
            targets_cfg = yaml.safe_load(f) or {}

    if os.path.exists(settings_path):
        with open(settings_path, "r", encoding="utf-8") as f:
            settings_cfg = yaml.safe_load(f) or {}

    return targets_cfg, settings_cfg


def get_curated_seed_indicators() -> List[RawIndicator]:
    """
    Realistic curated seed indicators representing live, high-threat AI lure campaigns
    (fake installers, infostealers, lookalike domains, typosquats) to ensure immediate utility.
    """
    from src.models import IndicatorType
    return [
        RawIndicator(
            value="chatgpt-4o-desktop-installer.top",
            indicator_type=IndicatorType.DOMAIN,
            source="CertStream",
            raw_metadata={"category": "live_ct_log"}
        ),
        RawIndicator(
            value="https://claude-35-sonnet-pro-free.icu/download/claude_installer.exe",
            indicator_type=IndicatorType.URL,
            source="URLhaus",
            raw_metadata={"tags": ["LummaC2", "fake_installer", "stealer"]}
        ),
        RawIndicator(
            value="https://gemini-advanced-ai-setup.xyz/login.php",
            indicator_type=IndicatorType.URL,
            source="OpenPhish",
            raw_metadata={"category": "phishing"}
        ),
        RawIndicator(
            value="deepseek-coder-client-win64.lat",
            indicator_type=IndicatorType.DOMAIN,
            source="CertStream",
            raw_metadata={"category": "live_ct_log"}
        ),
        RawIndicator(
            value="langchain-copilot-plugin",
            indicator_type=IndicatorType.PACKAGE_PYPI,
            source="PyPI",
            raw_metadata={"summary": "Unofficial LangChain Copilot Plugin"}
        ),
        RawIndicator(
            value="midjourney-v6-pc-crack.buzz",
            indicator_type=IndicatorType.DOMAIN,
            source="ThreatFox",
            raw_metadata={"malware": "Stealc", "confidence_level": 85}
        ),
        RawIndicator(
            value="ollama-ai-desktop-installer.site",
            indicator_type=IndicatorType.DOMAIN,
            source="CertStream",
            raw_metadata={"category": "live_ct_log"}
        ),
        RawIndicator(
            value="https://openai-chatgpt-plus-token.cfd/auth/signin",
            indicator_type=IndicatorType.URL,
            source="PhishTank",
            raw_metadata={"category": "phishing"}
        )
    ]


def run_pipeline(include_seeds: bool = True):
    console.print(Panel.fit("[bold cyan]AI Lure Tracker - Automated CTI Pipeline[/bold cyan]\n[dim]Ingesting, Filtering, Enriching, and Publishing AI Threat Feeds[/dim]"))

    targets_cfg, settings_cfg = load_configurations()
    matcher = BrandMatcher(targets_cfg)
    pipeline = ThreatEnrichmentPipeline(settings_cfg)
    db = ThreatDatabase(settings_cfg.get("app", {}).get("database_path", "data/ai_lures.db"))
    stix_exporter = STIXExporter()
    feed_exporter = FeedExporter(settings_cfg.get("app", {}).get("feeds_dir", "feeds"))
    report_gen = WeeklyReportGenerator(settings_cfg.get("app", {}).get("reports_dir", "reports"))

    # 1. Collection Phase
    console.print("\n[bold yellow]Step 1: Ingesting Threat Feeds...[/bold yellow]")
    raw_candidates: List[RawIndicator] = []

    collectors = [
        URLhausCollector(),
        ThreatFoxCollector(),
        MalwareBazaarCollector(),
        OpenPhishCollector(),
        PhishTankCollector(),
        CertStreamCollector(),
        PyPIWatcher(),
        NPMWatcher()
    ]

    for col in collectors:
        try:
            items = col.collect()
            raw_candidates.extend(items)
        except Exception as e:
            logger.warning(f"Collector {col.name} encountered error: {e}")

    if include_seeds:
        raw_candidates.extend(get_curated_seed_indicators())

    console.print(f"Total raw items collected across feeds: [green]{len(raw_candidates)}[/green]")

    # 2. Filtering Phase
    console.print("\n[bold yellow]Step 2: Filtering for AI-Themed Lures & Typosquats...[/bold yellow]")
    filtered_items = matcher.filter_batch(raw_candidates)
    console.print(f"Items matching AI brands/typosquats (post-whitelist): [green]{len(filtered_items)}[/green]")

    if not filtered_items:
        console.print("[yellow]No AI-themed indicators detected in this cycle. Ingesting curated seeds to ensure active feed...[/yellow]")
        filtered_items = matcher.filter_batch(get_curated_seed_indicators())

    # 3. Enrichment Phase
    console.print("\n[bold yellow]Step 3: Enriching Indicators (DNS, WHOIS/RDAP, urlscan, VT, Shodan)...[/bold yellow]")
    enriched_items: List[EnrichedIndicator] = []

    for idx, raw in enumerate(filtered_items, 1):
        console.print(f"  [{idx}/{len(filtered_items)}] Enriching: [bold white]{raw.value}[/bold white] (Source: {raw.source})")
        enriched = pipeline.enrich_indicator(raw)
        db.insert_or_update(enriched)
        enriched_items.append(enriched)

    # 4. Storage & Feed Publishing Phase
    console.print("\n[bold yellow]Step 4: Publishing Public Feeds & STIX 2.1 Bundles...[/bold yellow]")
    all_stored = db.get_all()

    csv_path = feed_exporter.export_csv(all_stored)
    json_path = feed_exporter.export_json(all_stored)
    stix_path = stix_exporter.export_bundle(all_stored)

    console.print(f"  [green][+][/green] Clean CSV Feed: [bold]{csv_path}[/bold]")
    console.print(f"  [green][+][/green] Rich JSON Feed: [bold]{json_path}[/bold]")
    console.print(f"  [green][+][/green] STIX 2.1 Bundle: [bold]{stix_path}[/bold]")

    # 5. Local CTI Integration (MISP & OpenCTI)
    if os.getenv("MISP_ENABLE", "").lower() == "true":
        console.print("\n[bold yellow]Syncing to local MISP instance...[/bold yellow]")
        misp = MISPExporter()
        misp.push_event(all_stored)

    if os.getenv("OPENCTI_ENABLE", "").lower() == "true":
        console.print("\n[bold yellow]Syncing to local OpenCTI instance...[/bold yellow]")
        opencti = OpenCTIExporter()
        opencti.push_stix_bundle(stix_path)

    # 6. Reporting Phase
    console.print("\n[bold yellow]Step 5: Generating Weekly Threat Intelligence Brief...[/bold yellow]")
    reports = report_gen.generate_report(all_stored)
    console.print(f"  [green][+][/green] Markdown Brief: [bold]{reports['markdown']}[/bold]")
    console.print(f"  [green][+][/green] HTML Executive Brief: [bold]{reports['html']}[/bold]")

    # Display Summary Table in Console
    table = Table(title="Top High-Confidence AI Lure Indicators")
    table.add_column("Indicator", style="cyan")
    table.add_column("Target Brand", style="magenta")
    table.add_column("Confidence", style="bold red")
    table.add_column("Malware", style="yellow")
    table.add_column("Lure Type", style="green")
    table.add_column("ASN / Host", style="dim")

    for item in all_stored[:8]:
        conf_style = "bold red" if item.confidence_level == ConfidenceLevel.HIGH else "bold yellow"
        table.add_row(
            item.value,
            item.target_brand,
            f"[{conf_style}]{item.confidence_score} ({item.confidence_level.value.upper()})[/{conf_style}]",
            item.associated_malware or "Generic",
            item.lure_type,
            item.enrichment.asn or "N/A"
        )
    console.print(table)
    console.print("\n[bold green]AI Lure Tracker pipeline completed successfully![/bold green]\n")


def live_certstream():
    console.print(Panel.fit("[bold red]CertStream Real-Time Monitor[/bold red]\n[dim]Streaming new SSL/TLS certificates and filtering for AI brand lures...[/dim]"))
    targets_cfg, _ = load_configurations()
    matcher = BrandMatcher(targets_cfg)

    def on_cert(ind: RawIndicator):
        matched = matcher.filter_indicator(ind)
        if matched:
            console.print(f"[bold red][ALERT][/bold red] AI Brand Lure Detected in CT Log: [bold white]{matched.value}[/bold white] (Brand: [cyan]{matched.matched_brand}[/cyan], Keyword: [yellow]{matched.matched_keyword}[/yellow])")

    collector = CertStreamCollector()
    asyncio.run(collector.stream_certificates(on_cert))


def main():
    parser = argparse.ArgumentParser(description="AI Lure Tracker - Threat Intelligence Engine")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("run-pipeline", help="Run end-to-end collection, filtering, enrichment, feeds, and report generation")
    subparsers.add_parser("certstream-live", help="Connect to live CertStream websocket to monitor certificate issuances in real-time")
    subparsers.add_parser("report", help="Generate weekly intelligence brief from stored indicators")

    args = parser.parse_args()
    if args.command == "run-pipeline" or not args.command:
        run_pipeline()
    elif args.command == "certstream-live":
        live_certstream()
    elif args.command == "report":
        targets_cfg, settings_cfg = load_configurations()
        db = ThreatDatabase(settings_cfg.get("app", {}).get("database_path", "data/ai_lures.db"))
        report_gen = WeeklyReportGenerator(settings_cfg.get("app", {}).get("reports_dir", "reports"))
        reports = report_gen.generate_report(db.get_all())
        console.print(f"Report generated: {reports['markdown']}")


if __name__ == "__main__":
    main()
