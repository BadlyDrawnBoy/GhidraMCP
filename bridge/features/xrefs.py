"""Cross-reference search helpers."""

from typing import Dict, List

from ..ghidra.client import GhidraClient


def search_xrefs_to(
    client: GhidraClient,
    *,
    address: str,
    query: str,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, object]:
    """Search cross-references to ``address`` and return a paginated response."""

    try:
        address_value = int(address, 16)
    except ValueError as exc:  # pragma: no cover - validated earlier
        raise ValueError(f"Invalid address: {address}") from exc

    raw_results = client.search_xrefs_to(address_value, query)

    items: List[Dict[str, str]] = []
    for entry in raw_results:
        addr_val = entry.get("addr")
        context = entry.get("context", "")
        if not isinstance(addr_val, int):
            continue
        context_text = str(context)
        items.append(
            {
                "from_address": f"0x{addr_val:08x}",
                "context": context_text,
            }
        )

    total_results = len(items)
    page = offset // limit if limit > 0 else 0
    paginated_items = items[offset : offset + limit]

    return {
        "address": f"0x{address_value:08x}",
        "query": query,
        "total_results": total_results,
        "page": page,
        "limit": limit,
        "items": paginated_items,
    }
