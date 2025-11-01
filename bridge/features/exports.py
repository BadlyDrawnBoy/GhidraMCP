from typing import Dict, List

from ..ghidra.client import GhidraClient


def search_exports(
    client: GhidraClient,
    *,
    query: str,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, object]:
    """Search for exported symbols matching ``query`` and return paginated results."""

    raw_results = client.search_exports(query)

    items: List[Dict[str, str]] = []
    for line in raw_results:
        if "->" not in line:
            continue
        name_part, _, address_part = line.partition("->")
        name = name_part.strip()
        address = address_part.strip()
        if not name or not address:
            continue
        if not address.startswith("0x"):
            address = f"0x{address}"
        items.append({"name": name, "address": address})

    total_results = len(items)
    page = offset // limit if limit > 0 else 0
    paginated_items = items[offset : offset + limit]

    return {
        "query": query,
        "total_results": total_results,
        "page": page,
        "limit": limit,
        "items": paginated_items,
    }
