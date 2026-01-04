import copy
from typing import Any, Dict, Optional

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

Document = dict[str, Any]


class InMemoryInsertOneResult:
    def __init__(self, inserted_id: ObjectId) -> None:
        self.inserted_id = inserted_id


class InMemoryUpdateResult:
    def __init__(self, matched_count: int) -> None:
        self.matched_count = matched_count


class InMemoryCursor:
    def __init__(self, documents: list[Document]) -> None:
        self._documents = documents
        self._iter = iter(self._documents)

    def sort(self, key: str, direction: int) -> "InMemoryCursor":
        reverse = direction == -1
        self._documents.sort(key=lambda doc: (doc.get(key) is None, doc.get(key)), reverse=reverse)
        self._iter = iter(self._documents)
        return self

    def __aiter__(self) -> "InMemoryCursor":
        self._iter = iter(self._documents)
        return self

    async def __anext__(self) -> Document:
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration


class InMemoryCollection:
    def __init__(self, name: str) -> None:
        self._name = name
        self._documents: list[Document] = []
        self._unique_fields: set[str] = set()

    def _clone_doc(self, doc: Document) -> Document:
        return copy.deepcopy(doc)

    def _matches(self, doc: Document, filt: Optional[Dict[str, Any]]) -> bool:
        if not filt:
            return True
        for key, value in filt.items():
            if doc.get(key) != value:
                return False
        return True

    def _project(self, doc: Document, projection: Optional[Dict[str, Any]]) -> Document:
        if projection is None:
            return self._clone_doc(doc)
        include_id = projection.get("_id", 1)
        projected: Document = {}
        if include_id:
            projected["_id"] = doc.get("_id")
        for key, flag in projection.items():
            if key == "_id" or not flag:
                continue
            if key in doc:
                projected[key] = doc[key]
        return self._clone_doc(projected)

    async def create_index(self, key: str, unique: bool = False, **_: Any) -> str:
        if unique:
            self._unique_fields.add(key)
        return f"{key}_idx"

    async def find_one(self, filt: Optional[Dict[str, Any]] = None) -> Optional[Document]:
        for doc in self._documents:
            if self._matches(doc, filt):
                return self._clone_doc(doc)
        return None

    def find(self, filt: Optional[Dict[str, Any]] = None, projection: Optional[Dict[str, Any]] = None) -> "InMemoryCursor":
        results: list[Document] = []
        for doc in self._documents:
            if self._matches(doc, filt):
                results.append(self._project(doc, projection))
        return InMemoryCursor(results)

    async def insert_one(self, doc: Document) -> InMemoryInsertOneResult:
        stored = self._clone_doc(doc)
        stored.setdefault("_id", ObjectId())
        for unique_field in self._unique_fields:
            for existing in self._documents:
                if existing.get(unique_field) == stored.get(unique_field):
                    raise DuplicateKeyError(f"Duplicate value for {unique_field}")
        self._documents.append(stored)
        return InMemoryInsertOneResult(stored["_id"])

    async def update_one(self, filt: Dict[str, Any], update: Dict[str, Any]) -> InMemoryUpdateResult:
        set_values = update.get("$set", {})
        for idx, doc in enumerate(self._documents):
            if not self._matches(doc, filt):
                continue
            for unique_field in self._unique_fields:
                if unique_field in set_values:
                    for existing in self._documents:
                        if existing is doc:
                            continue
                        if existing.get(unique_field) == set_values[unique_field]:
                            raise DuplicateKeyError(f"Duplicate value for {unique_field}")
            updated = self._clone_doc(doc)
            for key, value in set_values.items():
                updated[key] = value
            self._documents[idx] = updated
            return InMemoryUpdateResult(1)
        return InMemoryUpdateResult(0)


class InMemoryDatabase:
    def __init__(self) -> None:
        self._collections: Dict[str, InMemoryCollection] = {}

    def __getitem__(self, name: str) -> InMemoryCollection:
        if name not in self._collections:
            self._collections[name] = InMemoryCollection(name)
        return self._collections[name]


class InMemoryClient:
    def __init__(self) -> None:
        self._db = InMemoryDatabase()

    def get_database(self) -> InMemoryDatabase:
        return self._db
