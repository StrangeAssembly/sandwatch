import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest  # noqa: E402
from todo import TodoList  # noqa: E402


def test_add_and_pending():
    t = TodoList()
    t.add("write tests")
    t.add("ship it")
    assert t.pending() == ["write tests", "ship it"]


def test_complete():
    t = TodoList()
    i = t.add("one")
    t.complete(i)
    assert t.pending() == []


def test_empty_title_rejected():
    with pytest.raises(ValueError):
        TodoList().add("   ")
