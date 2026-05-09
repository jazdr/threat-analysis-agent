"""CLI 진입점: 대화형 위협 인텔리전스 분석 에이전트"""

import sys
from agent import ThreatIntelAgent
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax


def print_banner(console: Console):
    console.print(Panel.fit(
        "[bold cyan]ThreatIntel-Agent[/bold cyan]\n"
        "[dim]자연어 기반 위협 인텔리전스 분석 CLI[/dim]",
        border_style="cyan"
    ))
    console.print("[dim]명령어: [bold]/quit[/bold] 종료, [bold]/schema[/bold] 스키마 보기, [bold]/help[/bold] 도움말[/dim]\n")


def print_result(console: Console, result: dict):
    """에이전트 결과를 Rich 스타일로 출력"""
    if result.get("error"):
        console.print(Panel(f"[bold red]오류:[/bold red] {result['error']}", border_style="red"))
        return

    # SQL
    sql = result.get("sql", "")
    console.print(Panel(
        Syntax(sql, "sql", theme="monokai", line_numbers=False),
        title="[bold green]생성된 SQL[/bold green]",
        border_style="green"
    ))

    # 결과 테이블
    rows = result.get("rows")
    columns = result.get("columns")
    if rows and columns:
        table = Table(title="[bold yellow]쿼리 결과[/bold yellow]", show_lines=True)
        for col in columns:
            table.add_column(col, overflow="fold")
        for row in rows[:50]:  # 최대 50행만 표시
            table.add_row(*[str(v) for v in row.values()])
        if len(rows) > 50:
            table.add_row(*["..."] * len(columns))
            table.caption = f"총 {len(rows)}행 중 50행 표시"
        console.print(table)
    else:
        console.print("[dim]결과가 없습니다.[/dim]")

    # 분석 의견
    analysis = result.get("analysis", "")
    if analysis:
        console.print(Panel(
            analysis,
            title="[bold magenta]분석 의견[/bold magenta]",
            border_style="magenta"
        ))


def main():
    console = Console()
    agent = ThreatIntelAgent()

    print_banner(console)

    # 스타트업 시 스키마 프리로드 (선택)
    with console.status("[cyan]DB 스키마를 불러오는 중...[/cyan]"):
        _ = agent.schema

    while True:
        try:
            question = console.input("[bold blue]질문[/bold blue] > ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]종료합니다.[/dim]")
            break

        if not question:
            continue

        if question.lower() in ("/quit", "/exit", ":q"):
            console.print("[dim]종료합니다.[/dim]")
            break

        if question.lower() == "/schema":
            console.print(Panel(
                Syntax(agent.schema, "sql", theme="monokai", line_numbers=False),
                title="DB Schema",
                border_style="blue"
            ))
            continue

        if question.lower() in ("/help", "/?"):
            console.print(
                "[bold]/quit[/bold] - 종료\n"
                "[bold]/schema[/bold] - DB 스키마 출력\n"
                "[bold]/help[/bold] - 이 도움말"
            )
            continue

        with console.status("[cyan]에이전트가 분석 중...[/cyan]"):
            result = agent.run(question)

        print_result(console, result)
        console.print("")


if __name__ == "__main__":
    main()
