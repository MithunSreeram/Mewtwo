"""Mewtwo TUI — live dashboard powered by Textual."""

from __future__ import annotations

from pathlib import Path


def launch_dashboard() -> None:
    """Entry point: launch the Textual TUI dashboard."""
    try:
        from textual.app import App, ComposeResult
        from textual.widgets import (
            Header, Footer, Static, DataTable, Label, TabbedContent, TabPane,
        )
        from textual.containers import Container, Horizontal, Vertical
        from textual.reactive import reactive
        from textual import work
    except ImportError:
        raise ImportError(
            "textual is required for the TUI dashboard.\n"
            "Install it with: pip install 'mewtwo[tui]'"
        )

    from . import config
    from .db import get_db

    # ------------------------------------------------------------------
    # Widgets
    # ------------------------------------------------------------------

    class StatCard(Static):
        """Small stat card showing a label + value."""

        def __init__(self, label: str, value: str, color: str = "cyan", **kwargs):
            super().__init__(**kwargs)
            self._label = label
            self._value = value
            self._color = color

        def render(self):
            return (
                f"[bold {self._color}]{self._value}[/bold {self._color}]\n"
                f"[dim]{self._label}[/dim]"
            )

    # ------------------------------------------------------------------
    # App
    # ------------------------------------------------------------------

    class MewtwoApp(App):
        """Mewtwo live dashboard."""

        CSS = """
        Screen {
            background: #0d1117;
        }

        Header {
            background: #161b22;
            color: #58a6ff;
        }

        Footer {
            background: #161b22;
        }

        .stat-row {
            height: 5;
            margin: 1 0;
            layout: horizontal;
        }

        StatCard {
            background: #161b22;
            border: tall #30363d;
            padding: 0 2;
            margin: 0 1;
            min-width: 18;
            height: 5;
            content-align: center middle;
            text-align: center;
        }

        DataTable {
            background: #0d1117;
            border: tall #30363d;
        }

        TabbedContent {
            background: #0d1117;
        }

        .section-title {
            color: #58a6ff;
            text-style: bold;
            padding: 1 0 0 1;
        }
        """

        BINDINGS = [
            ("r", "refresh", "Refresh"),
            ("q", "quit", "Quit"),
        ]

        TITLE = "Mewtwo — Bug Bounty Dashboard"

        def __init__(self, db_path: Path | None = None, **kwargs):
            super().__init__(**kwargs)
            self._db_path = db_path

        def compose(self) -> ComposeResult:
            yield Header()
            with TabbedContent():
                with TabPane("Overview", id="overview"):
                    yield Container(
                        Horizontal(
                            StatCard("Subdomains", "—", "cyan", id="stat_subs"),
                            StatCard("Alive Hosts", "—", "green", id="stat_alive"),
                            StatCard("URLs", "—", "blue", id="stat_urls"),
                            StatCard("Vectors", "—", "yellow", id="stat_vectors"),
                            StatCard("Findings", "—", "red", id="stat_findings"),
                            classes="stat-row",
                        )
                    )
                    yield Label("Recent Findings", classes="section-title")
                    yield DataTable(id="findings_table")

                with TabPane("Recon", id="recon"):
                    yield Label("Subdomains", classes="section-title")
                    yield DataTable(id="subs_table")

                with TabPane("Attack Surface", id="surface"):
                    yield Label("Attack Vectors", classes="section-title")
                    yield DataTable(id="vectors_table")

                with TabPane("Hunt", id="hunt"):
                    yield Label("Findings", classes="section-title")
                    yield DataTable(id="all_findings_table")

            yield Footer()

        def on_mount(self) -> None:
            self._setup_tables()
            self._load_data()

        def _setup_tables(self) -> None:
            ft = self.query_one("#findings_table", DataTable)
            ft.add_columns("Severity", "Title", "URL", "Status")

            st = self.query_one("#subs_table", DataTable)
            st.add_columns("Hostname", "Alive", "Status Code", "Sources")

            vt = self.query_one("#vectors_table", DataTable)
            vt.add_columns("Category", "Title", "Risk", "Checked", "URL")

            aft = self.query_one("#all_findings_table", DataTable)
            aft.add_columns("ID", "Severity", "Class", "Title", "URL", "Status")

        def _load_data(self) -> None:
            if not self._db_path or not self._db_path.exists():
                return

            try:
                db = get_db(self._db_path)
                tables = db.table_names()

                targets = list(db["targets"].rows) if "targets" in tables else []
                if not targets:
                    return
                tid = targets[0]["id"]
                target_name = targets[0].get("name", "Unknown")
                self.title = f"Mewtwo — {target_name}"

                # Stats
                subs_total = db["subdomains"].count_where("target_id = ?", [tid]) if "subdomains" in tables else 0
                subs_alive = db["subdomains"].count_where("target_id = ? AND is_alive = 1", [tid]) if "subdomains" in tables else 0
                urls = db["urls"].count_where("target_id = ?", [tid]) if "urls" in tables else 0
                vectors = db["attack_vectors"].count_where("target_id = ?", [tid]) if "attack_vectors" in tables else 0
                findings = db["findings"].count_where("target_id = ?", [tid]) if "findings" in tables else 0

                self.query_one("#stat_subs", StatCard)._value = str(subs_total)
                self.query_one("#stat_alive", StatCard)._value = str(subs_alive)
                self.query_one("#stat_urls", StatCard)._value = str(urls)
                self.query_one("#stat_vectors", StatCard)._value = str(vectors)
                self.query_one("#stat_findings", StatCard)._value = str(findings)
                for w in self.query("StatCard"):
                    w.refresh()

                # Recent findings table (overview)
                ft = self.query_one("#findings_table", DataTable)
                ft.clear()
                if "findings" in tables:
                    for row in db["findings"].rows_where(
                        "target_id = ?", [tid], order_by="discovered_at DESC", limit=20
                    ):
                        sev = row.get("severity", "?")
                        sev_styled = {
                            "critical": f"[bold red]{sev}[/bold red]",
                            "high": f"[yellow]{sev}[/yellow]",
                            "medium": f"[blue]{sev}[/blue]",
                            "low": f"[dim]{sev}[/dim]",
                        }.get(sev, sev)
                        ft.add_row(
                            sev_styled,
                            row.get("title", "")[:55],
                            row.get("url", "")[:45],
                            row.get("status", ""),
                        )

                # Subdomains table
                st = self.query_one("#subs_table", DataTable)
                st.clear()
                if "subdomains" in tables:
                    import json
                    for row in db["subdomains"].rows_where(
                        "target_id = ?", [tid], order_by="is_alive DESC", limit=100
                    ):
                        alive = "[green]✓[/green]" if row.get("is_alive") else "[red]✗[/red]"
                        sources = ", ".join(json.loads(row.get("sources_json") or "[]"))
                        st.add_row(
                            row["hostname"],
                            alive,
                            str(row.get("status_code") or "—"),
                            sources,
                        )

                # Vectors table
                vt = self.query_one("#vectors_table", DataTable)
                vt.clear()
                if "attack_vectors" in tables:
                    for row in db["attack_vectors"].rows_where(
                        "target_id = ?", [tid], order_by="risk_rating", limit=100
                    ):
                        checked = "[green]✓[/green]" if row.get("checked") else "[dim]pending[/dim]"
                        vt.add_row(
                            row.get("category", ""),
                            row.get("title", "")[:50],
                            row.get("risk_rating", ""),
                            checked,
                            row.get("url", "")[:45],
                        )

                # All findings
                aft = self.query_one("#all_findings_table", DataTable)
                aft.clear()
                if "findings" in tables:
                    for row in db["findings"].rows_where("target_id = ?", [tid]):
                        aft.add_row(
                            row["id"][:8],
                            row.get("severity", ""),
                            row.get("vuln_class", ""),
                            row.get("title", "")[:45],
                            row.get("url", "")[:40],
                            row.get("status", ""),
                        )

            except Exception as e:
                self.notify(f"Load error: {e}", severity="error")

        def action_refresh(self) -> None:
            self._load_data()
            self.notify("Dashboard refreshed", timeout=2)

    ws = config.active_workspace()
    db_path = config.db_path(ws) if ws else None
    MewtwoApp(db_path=db_path).run()
