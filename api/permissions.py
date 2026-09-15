"""Least-privilege authorization rules for administrative API actions."""

from rest_framework.permissions import BasePermission


class CanManageWhitelist(BasePermission):
    """Require staff status plus both permissions used by this upsert endpoint."""

    message = "Whitelist management permission is required."
    required_permissions = (
        "api.add_whitelistdomain",
        "api.change_whitelistdomain",
    )

    def has_permission(self, request, _view):
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and user.is_active
            and user.is_staff
            and user.has_perms(self.required_permissions)
        )


def can_view_scan_activity(user):
    """Return whether a user may view submitted domains in recent activity."""
    return bool(
        user
        and user.is_authenticated
        and user.is_active
        and user.is_staff
        and user.has_perm("api.view_scanlog")
    )
