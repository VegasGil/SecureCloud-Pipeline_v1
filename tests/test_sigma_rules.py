import json
from pathlib import Path
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "detections" / "windows"
EVENTS_DIR = ROOT / "tests" / "events"


def _match_selection(sel: dict, event: dict) -> bool:
    for field, value in sel.items():
        op = None
        if "|" in field:
            field, op = field.split("|", 1)
        ev = event.get(field)
        if ev is None:
            return False
        if op == "endswith":
            if not str(ev).endswith(value):
                return False
        elif op == "startswith":
            if not str(ev).startswith(value):
                return False
        elif op == "contains":
            vals = value if isinstance(value, list) else [value]
            if not any(v in str(ev) for v in vals):
                return False
        else:
            if ev != value:
                return False
    return True


def _evaluate(rule: dict, event: dict) -> bool:
    det = rule["detection"]
    sel_results = {
        k: _match_selection(v, event) for k, v in det.items() if k != "condition"
    }
    cond = det["condition"]
    # soporta "A and B", "A or B", "A"
    tokens = cond.replace("(", " ").replace(")", " ").split()
    # evaluación simple izquierda-a-derecha; suficiente para reglas de 1-2 selecciones
    result = None
    op = None
    for tok in tokens:
        if tok == "and":
            op = "and"
        elif tok == "or":
            op = "or"
        else:
            val = sel_results.get(tok, False)
            if result is None:
                result = val
            elif op == "and":
                result = result and val
            elif op == "or":
                result = result or val
    return bool(result)


def _load_events(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _collect_cases():
    cases = []
    for rule_file in sorted(RULES_DIR.glob("*.yml")):
        rule = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        event_file = EVENTS_DIR / f"{rule_file.stem}.jsonl"
        if not event_file.exists():
            continue
        events = _load_events(event_file)
        for i, ev in enumerate(events):
            cases.append(
                pytest.param(rule, ev, rule_file.name, i, id=f"{rule_file.stem}[{i}]")
            )
    return cases


@pytest.mark.parametrize("rule,event,name,idx", _collect_cases())
def test_rule_match(rule, event, name, idx):
    expected = event.pop("_match", False)
    assert _evaluate(rule, event) is expected