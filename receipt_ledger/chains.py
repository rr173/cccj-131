"""Correction-chain analysis.

A correction is a line with its own identity that *withdraws* the target item or
*replaces* its ``action`` / ``occurred_at``.  Each correction has exactly one
parent (the item it corrects).  This module looks at the whole correction graph
and decides which original receipt (chain root) may still speak.

Rules
-----
* A node has at most one successor.  If two *different* corrections name the
  same parent, that parent is a ``correction_conflict``.  No branch is
  preferred -- not by import order, not by timestamp.
* Any directed cycle is an error.  Every node whose parent chain leads into the
  cycle is tainted as well.
* A correction whose parent is absent is ``pending``; it is kept (not dropped)
  because the parent may arrive later.
* Only a chain that is conflict-free, cycle-free and fully present contributes
  to status, and only through its *end* node.  Withdrawing the end leaves the
  original receipt with no effective action, but every node remains queryable.
* Taint is transitive: a correction below a conflicted or cyclic node cannot be
  used either, because the chain root is undecided.

The analysis is purely structural over the fact layer, so it can be redone after
every import and never depends on the current assignment.  It is the only place
that decides chain state; the engine consumes the result.
"""

from __future__ import annotations

from collections import defaultdict

__all__ = [
    "ChainInfo",
    "analyse",
    "CLEAN",
    "CONFLICT",
    "CYCLE",
    "PENDING",
]

CLEAN = "clean"
CONFLICT = "conflict"
CYCLE = "cycle"
PENDING = "pending"


class ChainInfo:
    """Result of one whole-graph correction analysis."""

    __slots__ = (
        "present", "parent_of", "children", "conflict_parents",
        "cycle_nodes", "state", "root_of", "end_of", "reason",
        "conflict_node_of_root",
    )

    def __init__(self):
        self.present = set()
        self.parent_of = {}
        self.children = {}
        self.conflict_parents = set()
        self.cycle_nodes = set()
        self.state = {}                  # node -> clean|conflict|cycle|pending
        self.root_of = {}                # node -> root key or None
        self.end_of = {}                 # clean root -> end key
        self.reason = {}                 # root/node -> explanation
        self.conflict_node_of_root = {}  # conflicted root -> branching node

    # -- convenience -------------------------------------------------------
    def end(self, root):
        return self.end_of.get(root)

    def path(self, root):
        """Node sequence root..end for a clean root (empty otherwise)."""
        if self.state.get(root) != CLEAN or root not in self.end_of:
            return []
        out = [root]
        node = root
        while node != self.end_of[root]:
            kids = self.children.get(node, [])
            if len(kids) != 1:
                raise AssertionError("clean chain with non-singleton successor")
            node = kids[0]
            out.append(node)
        return out

    def roots(self):
        return sorted(n for n, s in self.state.items()
                      if s in (CLEAN, CONFLICT) and self.root_of.get(n) == n)


def analyse(present, parent_of):
    """Analyse a correction graph.

    ``present``    set of all present line keys (originals and corrections)
    ``parent_of``  mapping correction key -> parent key (parent may be absent,
                   in which case the key is a synthetic ``ref:...`` marker)
    """
    info = ChainInfo()
    info.present = set(present)
    info.parent_of = dict(parent_of)

    children = defaultdict(list)
    for child in sorted(parent_of):
        children[parent_of[child]].append(child)
    info.children = {p: sorted(k) for p, k in children.items()}
    info.conflict_parents = {
        p for p, kids in info.children.items() if len(kids) > 1
    }

    # --- classify each node by walking its parent pointers -----------------
    # up[node] = ("root", root_key) | ("missing", None) | ("cycle", None)
    up = {}
    for start in sorted(info.present):
        if start in up:
            continue
        path = []
        index = {}
        cur = start
        while True:
            if cur in up:
                kind, root = up[cur]
                for node in path:
                    up[node] = (kind, root)
                break
            if cur in index:
                # the parent chain loops back onto itself
                cycle = path[index[cur]:]
                for node in cycle:
                    up[node] = ("cycle", None)
                    info.cycle_nodes.add(node)
                for node in path[: index[cur]]:
                    up[node] = ("cycle", None)
                    info.cycle_nodes.add(node)
                break
            index[cur] = len(path)
            path.append(cur)
            parent = info.parent_of.get(cur)
            if parent is None:
                # ``cur`` is the original item (chain root)
                for node in path:
                    up[node] = ("root", cur)
                break
            if parent not in info.present:
                for node in path:
                    up[node] = ("missing", None)
                break
            cur = parent

    # --- every node reachable from an origin, and per-root chain state -----
    roots = sorted(n for n, (kind, root) in up.items()
                   if kind == "root" and root == n)
    for root in roots:
        order = []
        seen = set()
        stack = [root]
        conflict_here = None
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            order.append(node)
            kids = info.children.get(node, [])
            if len(kids) > 1 and conflict_here is None:
                conflict_here = node
            stack.extend(kids)
        if conflict_here is None:
            node = root
            chain = [node]
            while info.children.get(node):
                node = info.children[node][0]
                chain.append(node)
            for node in order:
                info.state[node] = CLEAN
                info.root_of[node] = root
            info.end_of[root] = chain[-1]
            info.reason[root] = (
                f"clean chain of {len(chain)} node(s), end={chain[-1]}")
            for node in order:
                info.reason.setdefault(
                    node, f"member of clean chain rooted at {root}")
        else:
            for node in order:
                info.state[node] = CONFLICT
                info.root_of[node] = root
            info.conflict_node_of_root[root] = conflict_here
            info.reason[root] = (
                "correction_conflict: %d corrections target %s"
                % (len(info.children[conflict_here]), conflict_here))

    # --- nodes that never reach an origin ---------------------------------
    for node, (kind, _root) in up.items():
        if node in info.state:
            continue
        if kind == "missing":
            info.state[node] = PENDING
            info.root_of[node] = None
            info.reason[node] = (
                "pending: parent item %r not present yet"
                % (info.parent_of.get(node),))
        elif kind == "cycle":
            info.state[node] = CYCLE
            info.root_of[node] = None
            info.reason[node] = "correction cycle: parent chain loops"
        else:  # pragma: no cover - defensive
            raise AssertionError("unclassified correction node %r" % (node,))
    return info
