"""Independent, deliberately naive reference implementation.

This module is a *second opinion* used by the tests and the drills.  It is
written to be as dumb as possible:

* it reads the **fact tables only** (outbound attempts, DSN lines, correction
  lines, manual decisions) with plain SELECTs;
* it enumerates candidates itself with a Python triple loop -- no SQL matching
  clause is reused and no formal matcher, chain analyser or merge function is
  imported (it must not even import ``receipt_ledger.engine``);
* it traverses corrections with its own recursive walks;
* it recomputes every status from scratch on each call.

It is only viable for small inputs (O(receipts x attempts)); that is exactly
its purpose: an oracle for the incremental engine.

Independently reproduced conventions
------------------------------------
* canonical recipient: ASCII domain lowercased, local part byte-exact;
* candidate = same gateway, same recipient, ``sent_at <= occurred_at``, and
  equality on every queue/envelope condition the *root* item supplies;
* a correction may only change ``action`` / ``occurred_at``; one that restates
  a queue/envelope/recipient field with a different value, or introduces one,
  invalidates the whole chain;
* a clean chain contributes only its end node's action/time;
* two corrections on the same parent, or a correction cycle, excludes the whole
  chain (no branch is chosen);
* a correction whose parent is missing is pending and contributes nothing;
* last attempt per (delivery, recipient) = max ``(sent_at, attempt_id)`` with
  attempt_id compared by raw lexicographic order;
* both terminal actions on one attempt -> ``inconsistent``.
"""

from __future__ import annotations

import hashlib

__all__ = ["ReferenceSnapshot", "snapshot", "reference_summary",
           "reference_delivery_status"]

TERMINALS = ("delivered", "failed")


def _canon_recipient(raw):
    """Independent re-implementation of the recipient convention."""
    text = raw if isinstance(raw, str) else raw.decode("utf-8")
    if text.count("@") != 1:
        raise ValueError(f"unsupported address {raw!r}")
    local, domain = text.split("@", 1)
    if not local or not domain:
        raise ValueError(f"unsupported address {raw!r}")
    # the ``r:`` prefix is the ledger's stored signature tag; it is part of the
    # documented canonical form so a receipt/attempt comparison cannot confuse
    # an address with a queue identifier
    return b"r:" + (local + "@" + domain.lower()).encode()


def _fingerprint(cands):
    """Independent fingerprint: sorted canonical member strings, SHA-256."""
    members = sorted(
        "[\"%s\",\"%s\",\"%s\"]" % (d.replace("\\", "\\\\").replace('"', '\\"'),
                                    a.replace("\\", "\\\\").replace('"', '\\"'),
                                    r.hex())
        for d, a, r in cands)
    return hashlib.sha256("\n".join(members).encode()).hexdigest()


class ReferenceSnapshot:
    """All facts loaded once; every derived view brute-forced on demand."""

    def __init__(self, conn):
        idents = {r[0]: r[1].decode().removeprefix("i:")
                  for r in conn.execute("SELECT id, ident FROM gateway")}
        self.attempts = []
        for r in conn.execute(
                "SELECT gateway_row, delivery_id, attempt_id, recipient_text,"
                " queue_id, envelope_id, sent_at_us, sent_at_text"
                " FROM outbound_attempt ORDER BY id"):
            self.attempts.append({
                "gw": idents[r[0]], "delivery_id": r[1], "attempt_id": r[2],
                "recipient": _canon_recipient(r[3]),
                "queue_id": r[4], "envelope_id": r[5],
                "sent_at_us": r[6], "sent_at": r[7]})
        self.originals = []
        for r in conn.execute(
                "SELECT gateway_row, report_id, item_id, occurred_at_us,"
                " action, recipient_text, queue_id, envelope_id"
                " FROM dsn_line ORDER BY id"):
            self.originals.append({
                "key": f"dsn:{r[0]}:{r[1]}:{r[2]}",
                "gw": idents[r[0]], "report_id": r[1], "item_id": r[2],
                "occurred_at_us": r[3], "action": r[4],
                "recipient": _canon_recipient(r[5]),
                "queue_id": r[6], "envelope_id": r[7]})
        self.corrections = []
        for r in conn.execute(
                "SELECT gateway_row, report_id, item_id, target_report_id,"
                " target_item_id, occurred_at_us, action, recipient_text,"
                " queue_id, envelope_id FROM correction_line ORDER BY id"):
            self.corrections.append({
                "key": f"cor:{r[0]}:{r[1]}:{r[2]}",
                "gw": idents[r[0]], "report_id": r[1], "item_id": r[2],
                "target_report_id": r[3], "target_item_id": r[4],
                "occurred_at_us": r[5], "action": r[6],
                "recipient": (_canon_recipient(r[7])
                              if r[7] is not None else None),
                "queue_id": r[8], "envelope_id": r[9]})
        self.decisions = []
        for r in conn.execute(
                "SELECT gateway_row, root_report_id, root_item_id, delivery_id,"
                " attempt_id, recipient_sig, candidate_fp"
                " FROM manual_decision ORDER BY id"):
            self.decisions.append({
                "gw": idents[r[0]],
                "root": ("dsn:%s:%s" % (r[1], r[2])),
                "delivery_id": r[3], "attempt_id": r[4],
                "recipient": bytes(r[5]), "candidate_fp": r[6]})
        # identity lookup, including the gateway, so equal numbers on two
        # gateways stay distinct
        self._by_identity = {}
        for orig in self.originals:
            self._by_identity[(orig["gw"], orig["report_id"],
                               orig["item_id"])] = orig["key"]
        for cor in self.corrections:
            self._by_identity[(cor["gw"], cor["report_id"],
                               cor["item_id"])] = cor["key"]
        self._kids = {}
        for cor in self.corrections:
            self._kids.setdefault(self.resolve_target(cor), []).append(cor)

    # -- graph ------------------------------------------------------------- #
    def resolve_target(self, cor):
        return self._by_identity.get(
            (cor["gw"], cor["target_report_id"], cor["target_item_id"]),
            f"missing:{cor['gw']}:{cor['target_report_id']}:"
            f"{cor['target_item_id']}")

    def node(self, key):
        if key.startswith("dsn:"):
            for orig in self.originals:
                if orig["key"] == key:
                    return orig
            return None
        for cor in self.corrections:
            if cor["key"] == key:
                return cor
        return None

    def walk(self, node, stack=()):
        """Return (state, end_key).  States: clean|conflict|cycle|pending."""
        if node in stack:
            return "cycle", None
        children = self._kids.get(node, [])
        if len(children) > 1:
            return "conflict", None
        if not children:
            return "clean", node
        child = children[0]
        return self.walk(child["key"], stack + (node,))

    def chain_path(self, root):
        path = [root]
        node = root
        while True:
            kids = self._kids.get(node, [])
            if len(kids) != 1:
                break
            node = kids[0]["key"]
            if node in path:
                break
            path.append(node)
        return path

    def chain_state(self, root):
        state, end = self.walk(root)
        if state != "clean":
            return state, None
        for key in self.chain_path(root):
            if key.startswith("cor:"):
                node = self.node(key)
                if self.resolve_target(node).startswith("missing:"):
                    return "pending", None
        return "clean", end

    def invalid_correction(self, key):
        """True when a correction rewrites a matching field."""
        node = self.node(key)
        for field in ("recipient", "queue_id", "envelope_id"):
            supplied = node[field]
            if supplied is None:
                continue
            inherited = None
            cur = node
            seen = set()
            while cur is not None and cur["key"] not in seen:
                seen.add(cur["key"])
                parent_key = self.resolve_target(cur) \
                    if cur["key"].startswith("cor:") else None
                if parent_key is None:
                    break
                parent = self.node(parent_key)
                if parent is None:
                    break
                if parent[field] is not None:
                    inherited = parent[field]
                    break
                cur = parent
            if inherited is None or inherited != supplied:
                return True
        return False

    # -- candidates -------------------------------------------------------- #
    def candidates_for(self, item):
        """Brute-force candidate list for a chain root (plain Python loop)."""
        out = []
        for att in self.attempts:
            if att["gw"] != item["gw"]:
                continue
            if att["recipient"] != item["recipient"]:
                continue
            if att["sent_at_us"] > item["occurred_at_us"]:
                continue
            if item["queue_id"] is not None \
                    and att["queue_id"] != item["queue_id"]:
                continue
            if item["envelope_id"] is not None \
                    and att["envelope_id"] != item["envelope_id"]:
                continue
            out.append((att["delivery_id"], att["attempt_id"],
                        att["recipient"]))
        out.sort()
        return out

    # -- evaluation -------------------------------------------------------- #
    def evaluate(self):
        views = {}
        for orig in self.originals:
            state, end = self.chain_state(orig["key"])
            invalid = False
            if state == "clean":
                for key in self.chain_path(orig["key"]):
                    if key.startswith("cor:") and self.invalid_correction(key):
                        invalid = True
                        break
            end_node = self.node(end) if end else None
            effective_at = (end_node["occurred_at_us"] if end_node
                            else orig["occurred_at_us"])
            effective_action = None
            if end_node is not None and end_node["action"] != "withdraw":
                effective_action = end_node["action"]
            query = dict(orig)
            query["occurred_at_us"] = effective_at
            cands = self.candidates_for(query)
            fp = _fingerprint(cands)
            root_ident = ("dsn:%s:%s" % (orig["report_id"], orig["item_id"]))
            applied = [d for d in self.decisions
                       if d["gw"] == orig["gw"] and d["root"] == root_ident
                       and d["candidate_fp"] == fp]
            conflicting_decisions = False
            assignment = None
            if state == "clean" and not invalid and effective_action \
                    is not None:
                if applied:
                    choices = {(d["delivery_id"], d["attempt_id"],
                                d["recipient"]) for d in applied}
                    if len(choices) == 1:
                        choice = next(iter(choices))
                        if choice in cands:
                            assignment = choice
                    else:
                        conflicting_decisions = True
                elif len(cands) == 1:
                    assignment = cands[0]
            if state != "clean" or invalid:
                mark = "excluded"
            elif effective_action is None:
                mark = "withdrawn"
            elif conflicting_decisions:
                mark = "ambiguous"
            elif len(cands) == 0:
                mark = "unmatched"
            elif len(cands) == 1:
                mark = "unique"
            else:
                mark = "ambiguous"
            views[orig["key"]] = {
                "gw": orig["gw"],
                "state": "invalid" if invalid else state,
                "end": end, "fp": fp, "candidates": cands, "mark": mark,
                "action": effective_action, "occurred_at_us": effective_at,
                "assignment": assignment,
                "contributes": bool(assignment) and not invalid
                and state == "clean" and effective_action is not None,
                "path": self.chain_path(orig["key"])}
        return views

    def attempt_statuses(self):
        views = self.evaluate()
        actions = {}
        for view in views.values():
            if not view["contributes"]:
                continue
            # the gateway is part of an attempt's identity, so a receipt must
            # never credit an identically numbered attempt on another gateway
            actions.setdefault(
                (view["gw"], view["assignment"][0], view["assignment"][1],
                 view["assignment"][2]), []).append(view["action"])
        out = {}
        for att in self.attempts:
            # an attempt is per (gateway, delivery, attempt, recipient): the
            # same delivery/attempt id may target several recipients
            key = (att["gw"], att["delivery_id"], att["attempt_id"],
                   att["recipient"])
            out[key] = _status(actions.get(key, []))
        return out

    def delivery_statuses(self):
        per_attempt = self.attempt_statuses()
        grouped = {}
        for att in self.attempts:
            pair = (att["gw"], att["delivery_id"], att["recipient"])
            grouped.setdefault(pair, []).append(att)
        out = {}
        for pair, atts in grouped.items():
            ordered = sorted(atts, key=lambda a: (a["sent_at_us"],
                                                  a["attempt_id"]),
                             reverse=True)
            latest = ordered[0]
            out[pair] = {
                "status": per_attempt[(latest["gw"], latest["delivery_id"],
                                       latest["attempt_id"],
                                       latest["recipient"])],
                "latest_attempt_id": latest["attempt_id"]}
        return out


def _status(actions):
    has_delivered = "delivered" in actions
    has_failed = "failed" in actions
    if has_delivered and has_failed:
        return "inconsistent"
    if has_delivered:
        return "delivered"
    if has_failed:
        return "failed"
    if "delayed" in actions:
        return "delayed"
    return "awaiting"


def snapshot(conn):
    return ReferenceSnapshot(conn)


def reference_delivery_status(conn, gateway_id, delivery_id, recipient):
    pair = (gateway_id, delivery_id, _canon_recipient(recipient))
    statuses = ReferenceSnapshot(conn).delivery_statuses()
    if pair not in statuses:
        raise KeyError("no attempt for this delivery/recipient")
    return statuses[pair]


def reference_summary(conn):
    """Brute-force equivalent of the formal summary counts."""
    snap = ReferenceSnapshot(conn)
    views = snap.evaluate()
    deliveries = snap.delivery_statuses()
    counts = {}
    for info in deliveries.values():
        counts[info["status"]] = counts.get(info["status"], 0) + 1
    buckets = {}
    for view in views.values():
        buckets[view["mark"]] = buckets.get(view["mark"], 0) + 1
    return {"delivery_counts": counts,
            "receipt_buckets": buckets,
            "proven_delivered": counts.get("delivered", 0)}
