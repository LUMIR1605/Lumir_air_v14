"""Deterministic graph paths, pivots, adversarial review and dossier assembly."""

from collections import defaultdict, deque
import hashlib
from typing import Iterable, Mapping

from .enrichment import EnricherRegistry
from .models import (
    CaseDossier,
    CorrelationPath,
    GraphEntityType,
    GraphPivot,
    GraphStatus,
    IdentityCandidate,
    IdentityStatus,
    PivotBudget,
    ProfessionalFailureState,
)
from .store import GraphStore


def detect_circular_provenance(relations: Iterable[Mapping[str, object]]) -> tuple[tuple[str, ...], ...]:
    adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for relation in relations:
        if relation.get("relation_type") not in {"REFERENCES", "LINKS_TO", "MENTIONS", "MENTIONED_ON"}:
            continue
        adjacency[str(relation["source_entity_id"])].append(
            (str(relation["target_entity_id"]), str(relation["relation_id"]))
        )
    cycles: set[tuple[str, ...]] = set()

    def visit(node: str, nodes: tuple[str, ...], edges: tuple[str, ...]) -> None:
        for target, relation_id in adjacency.get(node, ()):
            if target in nodes:
                start = nodes.index(target)
                cycle = edges[start:] + (relation_id,)
                rotations = tuple(cycle[index:] + cycle[:index] for index in range(len(cycle)))
                cycles.add(min(rotations))
            elif len(nodes) < 8:
                visit(target, nodes + (target,), edges + (relation_id,))

    for start in sorted(adjacency):
        visit(start, (start,), ())
    return tuple(sorted(cycles))


class GraphPathEngine:
    def paths(self, snapshot: Mapping[str, object], *, max_hops: int = 4) -> tuple[CorrelationPath, ...]:
        nodes = {str(item["entity_id"]): item for item in snapshot.get("nodes", [])}
        relations = {str(item["relation_id"]): item for item in snapshot.get("edges", [])}
        adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for relation_id, relation in relations.items():
            if relation.get("status") == GraphStatus.REJECTED.value:
                continue
            adjacency[str(relation["source_entity_id"])].append(
                (str(relation["target_entity_id"]), relation_id)
            )
        circular_ids = {item for cycle in detect_circular_provenance(relations.values()) for item in cycle}
        values: dict[tuple[str, ...], CorrelationPath] = {}
        for start in sorted(nodes):
            queue = deque([(start, (start,), ())])
            while queue:
                current, entity_ids, relation_ids = queue.popleft()
                if relation_ids:
                    path = self._build(entity_ids, relation_ids, nodes, relations, circular_ids)
                    values[path.relation_sequence] = path
                if len(relation_ids) >= max_hops:
                    continue
                for target, relation_id in adjacency.get(current, ()):
                    if target not in entity_ids:
                        queue.append((target, entity_ids + (target,), relation_ids + (relation_id,)))
        return tuple(sorted(values.values(), key=lambda item: (-len(item.relation_sequence), -item.confidence,
                                                               item.path_id)))

    @staticmethod
    def _build(entity_ids, relation_ids, nodes, relations, circular_ids) -> CorrelationPath:
        edges = [relations[item] for item in relation_ids]
        weakest = min(float(item.get("confidence", 0.0)) for item in edges)
        groups = sorted({str(group) for item in edges for group in item.get("independence_groups", [])})
        evidence = tuple(dict.fromkeys(
            str(ref) for item in edges for ref in item.get("evidence_refs", [])
        ))
        circular = any(item in circular_ids for item in relation_ids)
        contradiction = any(item.get("status") == GraphStatus.REJECTED.value for item in edges)
        confidence = weakest * min(1.0, 0.8 + 0.08 * len(groups))
        if circular:
            confidence -= 0.25
        if contradiction:
            confidence -= 0.3
        confidence = round(max(0.0, min(0.94, confidence)), 3)
        sequence = []
        for index, entity_id in enumerate(entity_ids):
            node = nodes[entity_id]
            sequence.append(str(node.get("entity_type")))
            if index < len(edges):
                sequence.append(str(edges[index].get("relation_type")))
        reasons = [f"weakest link confidence: {weakest:.3f}", f"independent groups: {len(groups)}",
                   f"evidence count: {len(evidence)}"]
        if circular:
            reasons.append("circular provenance penalty applied")
        token = "|".join((*entity_ids, *relation_ids))
        return CorrelationPath(
            path_id="path-" + hashlib.sha256(token.encode()).hexdigest()[:20],
            entity_sequence=entity_ids, relation_sequence=relation_ids, evidence_refs=evidence,
            confidence=confidence, explanation=" -> ".join(sequence), reasons=tuple(reasons),
            independent_groups=tuple(groups),
        )


class GraphPivotPlanner:
    def __init__(self, *, registry: EnricherRegistry, budget: PivotBudget | None = None) -> None:
        self.registry = registry
        self.budget = budget or PivotBudget()

    def plan(
        self,
        *,
        snapshot: Mapping[str, object],
        store: GraphStore,
        contradictions: Iterable[str] = (),
        open_hypotheses: Iterable[Mapping[str, object]] = (),
    ) -> tuple[GraphPivot, ...]:
        nodes = tuple(snapshot.get("nodes", ()))
        edges = tuple(snapshot.get("edges", ()))
        if len(nodes) >= self.budget.max_entities or len(edges) >= self.budget.max_relations:
            return ()
        degree: dict[str, int] = defaultdict(int)
        for edge in edges:
            degree[str(edge["source_entity_id"])] += 1
            degree[str(edge["target_entity_id"])] += 1
        proposals: list[GraphPivot] = []
        hypothesis_bonus = 0.1 if tuple(open_hypotheses) else 0.0
        contradiction_bonus = 0.12 if tuple(contradictions) else 0.0
        for node in nodes:
            hop = int(node.get("attributes", {}).get("hop", 0))
            if hop >= self.budget.max_hops:
                continue
            try:
                entity_type = GraphEntityType(str(node["entity_type"]))
            except ValueError:
                continue
            for definition in self.registry.for_entity(entity_type):
                fingerprint = hashlib.sha256(
                    f"{snapshot['case_id']}|{node['entity_id']}|{definition.enricher_id}|{node['canonical_value']}".encode()
                ).hexdigest()
                duplicate = store.has_pivot(fingerprint)
                graph_value = definition.expected_information_gain
                reasons = ["expected information gain"]
                if degree[str(node["entity_id"])] == 0:
                    graph_value += 0.12
                    reasons.append("may connect an isolated graph cluster")
                if hypothesis_bonus:
                    graph_value += hypothesis_bonus
                    reasons.append("may test an open hypothesis")
                if contradiction_bonus:
                    graph_value += contradiction_bonus
                    reasons.append("may resolve a contradiction")
                graph_value = round(min(1.0, graph_value), 3)
                token = f"{node['entity_id']}|{definition.enricher_id}"
                proposals.append(GraphPivot(
                    pivot_id="gpivot-" + hashlib.sha256(token.encode()).hexdigest()[:20],
                    case_id=str(snapshot["case_id"]), source_entity_id=str(node["entity_id"]),
                    proposed_enricher=definition.enricher_id, proposed_input=str(node["canonical_value"]),
                    expected_information_gain=definition.expected_information_gain,
                    privacy_cost=definition.privacy_cost,
                    network_cost=0.0 if not definition.network_required else 0.6,
                    duplication_risk=1.0 if duplicate else 0.1, graph_value=graph_value,
                    reason="; ".join(reasons), status="SUPPRESSED_DUPLICATE" if duplicate else "PROPOSED",
                    execution_fingerprint=fingerprint, hop=hop + 1,
                ))
        proposals.sort(key=lambda item: (item.status != "PROPOSED", -item.graph_value, item.pivot_id))
        return tuple(proposals[:self.budget.max_pivots])


class GraphAdversarialVerifier:
    def review(self, *, snapshot: Mapping[str, object], paths: Iterable[CorrelationPath]) -> tuple[dict[str, object], ...]:
        cycles = detect_circular_provenance(snapshot.get("edges", ()))
        circular = {relation for cycle in cycles for relation in cycle}
        values = []
        for path in paths:
            challenges = []
            if len(path.independent_groups) < 2:
                challenges.append("insufficient independent evidence")
            if any(item in circular for item in path.relation_sequence):
                challenges.append("circular evidence dependency")
            node_types = {str(item["entity_id"]): str(item["entity_type"]) for item in snapshot.get("nodes", ())}
            if any(node_types.get(item) == "USERNAME" for item in path.entity_sequence):
                challenges.append("username collision alternative")
            edge_map = {str(item["relation_id"]): item for item in snapshot.get("edges", ())}
            if any(edge_map[item].get("attributes", {}).get("stale") for item in path.relation_sequence):
                challenges.append("stale-only relation")
            if any(edge_map[item].get("status") == "REJECTED" for item in path.relation_sequence):
                challenges.append("contradictory or rejected edge")
            if any(edge_map[item].get("attributes", {}).get("newer_conflict")
                   for item in path.relation_sequence):
                challenges.append("contradictory newer source")
            if any(item in challenges for item in (
                "circular evidence dependency", "contradictory or rejected edge", "contradictory newer source",
            )):
                result = "WEAKENED"
            elif not challenges and len(path.independent_groups) >= 2:
                result = "SURVIVES"
            else:
                result = "INCONCLUSIVE"
            values.append({"path_id": path.path_id, "result": result, "challenges": challenges or [
                "no configured deterministic challenge"
            ]})
        return tuple(values)


def build_identity_candidates(paths: Iterable[CorrelationPath]) -> tuple[IdentityCandidate, ...]:
    values = []
    for path in paths:
        if len(path.entity_sequence) < 2:
            continue
        token = "|".join(sorted((path.entity_sequence[0], path.entity_sequence[-1])))
        status = IdentityStatus.PLAUSIBLE if path.confidence >= 0.7 and len(path.independent_groups) >= 2 else IdentityStatus.OPEN
        values.append(IdentityCandidate(
            identity_candidate_id="identity-" + hashlib.sha256(token.encode()).hexdigest()[:20],
            entity_ids=(path.entity_sequence[0], path.entity_sequence[-1]), supporting_paths=(path.path_id,),
            opposing_paths=(), confidence=min(path.confidence, 0.79), status=status,
            reasons=("graph path candidate only; no identity conclusion",),
            unresolved_questions=("Can a reviewer verify independent evidence and exclude identifier recycling?",),
        ))
    unique = {item.identity_candidate_id: item for item in values}
    return tuple(unique[key] for key in sorted(unique))


def build_dossier(
    *,
    snapshot: Mapping[str, object],
    seeds: Iterable[Mapping[str, object]],
    paths: Iterable[CorrelationPath],
    intelligence: Mapping[str, object],
    pivots: Iterable[GraphPivot],
) -> CaseDossier:
    nodes = tuple(snapshot.get("nodes", ()))
    edges = tuple(snapshot.get("edges", ()))
    path_values = tuple(paths)
    failure_states = []
    if not edges:
        failure_states.append(ProfessionalFailureState.NO_VERIFIED_DATA.value)
    if edges and not any(len(item.independent_groups) >= 2 for item in path_values):
        failure_states.append(ProfessionalFailureState.INSUFFICIENT_INDEPENDENCE.value)
    contradictions = tuple(str(item) for item in intelligence.get("contradictions", ()))
    if contradictions:
        failure_states.append(ProfessionalFailureState.CONTRADICTORY.value)
    return CaseDossier(
        case_summary={"case_id": snapshot["case_id"], "graph_version": snapshot["graph_version"],
                      "failure_states": failure_states},
        seeds=tuple(dict(item) for item in seeds),
        key_entities=tuple(sorted(nodes, key=lambda item: (-float(item.get("confidence", 0)), str(item["entity_id"])))[:25]),
        key_relations=tuple(sorted(edges, key=lambda item: (-float(item.get("confidence", 0)), str(item["relation_id"])))[:25]),
        important_paths=tuple(item.to_dict() for item in path_values[:20]),
        hypotheses=tuple(intelligence.get("open_hypotheses", ())),
        verified_findings=tuple(item for item in edges if item.get("status") == "CONFIRMED"),
        rejected_findings=tuple(item for item in edges if item.get("status") == "REJECTED"),
        contradictions=contradictions,
        timeline=tuple(snapshot.get("timeline", ())),
        evidence_quality=tuple(intelligence.get("evidence_quality", ())),
        unresolved_questions=tuple(str(item) for item in intelligence.get("unresolved_questions", ())),
        recommended_pivots=tuple(item.to_dict() for item in pivots),
        reviewer_decisions=tuple(snapshot.get("reviewer_decisions", ())),
        coverage_summary={"entity_count": len(nodes), "relation_count": len(edges),
                          "path_count": len(path_values), "independent_path_count": sum(
                              len(item.independent_groups) >= 2 for item in path_values)},
    )
