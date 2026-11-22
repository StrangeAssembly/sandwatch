"""Minimal todo list logic (lab fixture)."""


class TodoList:
    def __init__(self):
        self._items = []

    def add(self, title):
        title = title.strip()
        if not title:
            raise ValueError("title must not be empty")
        self._items.append({"title": title, "done": False})
        return len(self._items) - 1

    def complete(self, index):
        self._items[index]["done"] = True

    def pending(self):
        return [i["title"] for i in self._items if not i["done"]]

    def __len__(self):
        return len(self._items)
