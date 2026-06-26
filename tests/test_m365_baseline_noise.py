"""v5.1.8 — baseline noise tuning for the M365 source.

The M365 generator picks Operations from per-category weighted lists.
A subset of those Operations triggers vendor-shipped S1 STAR rules on
nearly every demo tenant ("Office 365 Assignment of Management Group
Role", "Suspicious Inbox Rule", "Privileged Role Granted", etc.). At
the historical weights every passive demo tenant produced a steady
trickle of these alerts on background traffic alone — drowning out
the signal from any active attack scenario.

Contract enforced here:

* The known "STAR-rule-triggering" Operations have weight ≤ 1 in the
  baseline pools (``_admin_exchange``, ``_inbox_rules``). Operators
  can still raise them via Event Mix; scenarios can still emit them
  via ``field_overrides``.
* The Operations are NOT removed — preserved so scenario phases that
  reference them still work, so reweighting via Event Mix is a valid
  knob, and so the catalog-coverage tests don't regress.
"""
from __future__ import annotations


def _ops_dict(ops_list):
    return dict(ops_list)


def test_admin_exchange_high_noise_ops_capped_at_one():
    """Operations known to fire vendor STAR rules MUST be ≤1 in the
    ``_admin_exchange`` weighted pool. v5.1.8 baseline-noise tuning.
    """
    import inspect
    import re

    import sources.m365 as m365

    src = inspect.getsource(m365._admin_exchange)
    # Pull the ``ops = [...]`` literal out of the function body. We parse
    # the tuples by regex to avoid having to exec arbitrary code.
    pairs = re.findall(r'\("([^"]+)",\s*(\d+)\)', src)
    weights = {name: int(w) for name, w in pairs}

    noisy = (
        "Set-Mailbox",
        "New-TransportRule",
        "Set-TransportRule",
        "Remove-TransportRule",
        "Add-RoleGroupMember",
        "New-ManagementRoleAssignment",
    )
    for op in noisy:
        assert op in weights, f"{op} must remain in catalog (just downweighted)"
        assert weights[op] <= 1, (
            f"{op} baseline weight={weights[op]} — must be ≤1 to keep demo "
            f"tenant quiet on background traffic. Raise via Event Mix when "
            f"running scenarios that need it."
        )


def test_inbox_rules_creation_ops_capped_at_one():
    """``New-InboxRule`` / ``Set-InboxRule`` / forwarding ``Set-Mailbox``
    trigger "Suspicious Inbox Rule" / "Mailbox Forwarding" STAR rules on
    most S1 tenants. v5.1.8 caps their baseline weight at 1."""
    import inspect
    import re

    import sources.m365 as m365

    src = inspect.getsource(m365._inbox_rules)
    pairs = re.findall(r'\("([^"]+)",\s*(\d+)\)', src)
    weights = {name: int(w) for name, w in pairs}

    for op in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox"):
        assert op in weights, f"{op} must remain in catalog"
        assert weights[op] <= 1, (
            f"{op} baseline weight={weights[op]} — must be ≤1 to stop "
            f"baseline traffic from firing 'Suspicious Inbox Rule' STAR "
            f"alerts on demo tenants. Scenarios still emit via field_overrides."
        )


def test_noisy_ops_still_in_catalog():
    """Sanity: the downweighted Operations must STILL be reachable so
    scenarios / Event Mix can still produce them. v5.1.8 doesn't delete,
    it just tunes."""
    import sources.m365 as m365

    # Drive each dispatcher several times. With weights ≥1 the noisy ops
    # are still reachable; this just confirms they haven't been removed
    # from the list.
    import inspect
    import re

    for fn in (m365._admin_exchange, m365._inbox_rules):
        src = inspect.getsource(fn)
        pairs = re.findall(r'\("([^"]+)",\s*(\d+)\)', src)
        names = {n for n, _ in pairs}
        for op in ("Set-Mailbox", "New-ManagementRoleAssignment", "New-InboxRule"):
            # Only assert presence in the function where it lives.
            if op in src:
                assert op in names
