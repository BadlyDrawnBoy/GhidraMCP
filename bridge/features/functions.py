"""Function search and listing features."""

from typing import Dict, List

from ..ghidra.client import GhidraClient


def search_functions(
    client: GhidraClient,
    *,
    query: str,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, object]:
    """
    Search for functions matching the query and return paginated results.
    
    Args:
        client: Ghidra client instance
        query: Search query string
        limit: Maximum number of results per page
        offset: Number of results to skip
        
    Returns:
        Dictionary with query, total_results, page, limit, and items array
    """
    # Fetch all matching functions from Ghidra
    raw_results = client.search_functions(query)
    
    # Parse the raw results into structured objects
    items = []
    for line in raw_results:
        # Expected format: "function_name @ 0xaddress"
        if " @ " not in line:
            continue
        
        parts = line.split(" @ ", 1)
        if len(parts) != 2:
            continue
            
        name = parts[0].strip()
        address = parts[1].strip()
        
        # Ensure address has 0x prefix
        if not address.startswith("0x"):
            address = f"0x{address}"
            
        items.append({
            "name": name,
            "address": address,
        })
    
    # Calculate pagination
    total_results = len(items)
    page = offset // limit if limit > 0 else 0
    
    # Slice the results according to limit and offset
    paginated_items = items[offset:offset + limit]
    
    return {
        "query": query,
        "total_results": total_results,
        "page": page,
        "limit": limit,
        "items": paginated_items,
    }
