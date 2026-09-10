"""OpenAPI generation hooks."""


def exclude_legacy_api_routes(endpoints):
    """Document canonical v1 routes while compatibility aliases remain active."""
    return [
        endpoint
        for endpoint in endpoints
        if not (
            endpoint[0].startswith("/api/") and not endpoint[0].startswith("/api/v1/")
        )
    ]
