# Roadmap: Evolving from a Data Bridge to an Analysis Engine

## Executive Summary

This document outlines the current architectural limitations of the GhidraMCP bridge and proposes a strategic roadmap to evolve it from a simple data provider into a truly efficient engine for AI-driven reverse engineering.

The core problem is an architectural anti-pattern—**"Filter after Paginate"**—present in most data listing endpoints. This leads to incomplete search results and forces the controlling LLM to make uninformed, costly decisions.

The solution is a two-phase approach:
1.  **Immediate Fix:** Implement server-side search capabilities for all relevant endpoints and provide pagination metadata (`total_results`) to enable intelligent, iterative querying by the LLM.
2.  **Long-Term Vision:** Explore server-side relevance scoring to reduce the data sent to the LLM to only the most pertinent information, further minimizing token costs and cognitive load.

---

## The Core Problem: The "Filter After Paginate" Anti-Pattern

Currently, most endpoints that return lists of items (like strings, functions, or xrefs) operate as follows:

1.  The Java backend retrieves the **entire list** of items from Ghidra (potentially thousands).
2.  It then **slices** this list based on `limit` and `offset` parameters (e.g., gets the first 100 items).
3.  Only this small, paginated slice is sent back to the Python bridge and ultimately to the LLM.

This leads to a critical flaw: **any search or filter operation can only see the small slice of data, not the complete dataset.** If an LLM searches for the string "password" but that string is the 500th entry in the binary, a request for the first 100 strings will never find it. The system falsely reports "not found," leading to incorrect analysis.

This forces the LLM into a naive and expensive workflow: either blindly paginating through thousands of results or giving up.

---

## Phase 1: The Immediate Solution — Server-Side Search & Informed Pagination

To fix this fundamental issue, all listing endpoints must be refactored to follow a **"Search/Filter Before Paginate"** model.

### 1.1. Implement Server-Side Search

For each relevant entity type (strings, functions, imports, etc.), a dedicated search endpoint will be created (e.g., `/api/search_strings.json`).

*   **Responsibility:** The Java backend will be responsible for filtering the *entire dataset* based on a `query` parameter.
*   **Pagination:** The `limit` and `offset` parameters will be applied *only to the filtered result set*.

This ensures that a search query always operates on the complete ground truth available within Ghidra.

### 1.2. Provide Pagination Metadata

A simple list of results is not enough for an LLM to make strategic decisions. The response payload for all search endpoints must be enhanced to include crucial metadata:

```json
{
  "query": "password",
  "total_results": 1250,  // The total number of matches found
  "page": 1,              // The current page number
  "limit": 100,           // The number of items per page
  "items": [ /* ... the first 100 results ... */ ]
}
