"""Candidate generation by deterministic blocking.

Comparing every observation against every other one is quadratic and, worse,
compares pairs that share nothing — so a weak coincidence gets a score at all.
Blocking inverts it: index observations by a canonical key, and only compare
observations that landed in the same block.

Generating a candidate asserts nothing. It records that two observations share a
concrete, named key and are therefore worth scoring. Nothing here writes to the
graph, and nothing here merges anything.

Every candidate carries the strategy and the key it blocked on, so "why was this
pair ever considered?" has an answer that does not require re-running anything.
"""
from __future__ import annotations

from typing import Iterable, Mapping, Sequence

from app.core.normalization import NormalizationError, canonical_identifier
from app.core.resolution.extraction import (
    ATTR_ACCOUNT,
    ATTR_IMEI,
    ATTR_LOCALITY,
    ATTR_NAME,
    ATTR_PHONE,
    ATTR_SOURCE_ENTITY_REF,
)
from app.core.resolution.models import (
    BlockingStrategy,
    EntityObservation,
    EntityResolutionCandidate,
    candidate_id_for,
    resolution_lineage,
)
from app.core.resolution.policy import EntityTypePolicy


def canonical_entity_key(entity_key: str) -> str:
    """The form an entity key blocks and compares under.

    The same canonicalisation the extractors apply to a cross-source reference,
    so a register quoting `SUB-SYNTH-0001` lands in the same block as the
    operator record keyed on it.
    """
    try:
        return canonical_identifier(entity_key, "entity key")
    except NormalizationError:
        return entity_key.strip().upper()


class CandidateGenerator:
    """Blocks observations into candidate pairs according to policy."""

    def __init__(self, policy: EntityTypePolicy) -> None:
        self._policy = policy

    def generate(
        self, observations: Sequence[EntityObservation], created_at: str
    ) -> list[EntityResolutionCandidate]:
        """Return one candidate per distinct pair of observations.

        A pair that blocks on several keys is still one candidate: the strategy
        recorded is the first one in the policy's list that produced it, so the
        result never depends on iteration order.
        """
        candidates: dict[str, EntityResolutionCandidate] = {}
        for strategy in self._policy.blocking:
            for block_key, members in sorted(self._blocks(strategy, observations).items()):
                if len(members) < 2:
                    continue
                for left, right in _pairs(members):
                    if left.entity_key == right.entity_key:
                        # One entity as two sources named it is already one
                        # entity; there is nothing to resolve.
                        continue
                    lineage = resolution_lineage(
                        left.case_id, left.entity_type, left.entity_key, right.entity_key
                    )
                    candidate_id = candidate_id_for(
                        lineage, left.observation_id, right.observation_id
                    )
                    if candidate_id in candidates:
                        continue
                    candidates[candidate_id] = EntityResolutionCandidate(
                        candidate_id=candidate_id,
                        case_id=left.case_id,
                        entity_type=left.entity_type,
                        lineage_id=lineage,
                        left=left.ref,
                        right=right.ref,
                        blocking_strategy=strategy,
                        blocking_key=block_key,
                        created_at=created_at,
                    )
        return sorted(candidates.values(), key=lambda candidate: candidate.candidate_id)

    def _blocks(
        self, strategy: BlockingStrategy, observations: Sequence[EntityObservation]
    ) -> dict[str, list[EntityObservation]]:
        blocks: dict[str, list[EntityObservation]] = {}
        for observation in observations:
            for key in block_keys(strategy, observation):
                blocks.setdefault(key, []).append(observation)
        return blocks


def block_keys(strategy: BlockingStrategy, observation: EntityObservation) -> tuple[str, ...]:
    """The block keys one observation belongs to under one strategy.

    An observation can belong to two blocks under SOURCE_IDENTIFIER: it is both
    something another source may quote, and itself a quoter.
    """
    attributes = observation.attributes
    if strategy is BlockingStrategy.EXACT_PHONE:
        return _present(attributes, ATTR_PHONE)
    if strategy is BlockingStrategy.EXACT_IMEI:
        return _present(attributes, ATTR_IMEI)
    if strategy is BlockingStrategy.EXACT_ACCOUNT:
        return _present(attributes, ATTR_ACCOUNT)
    if strategy is BlockingStrategy.SOURCE_IDENTIFIER:
        return (canonical_entity_key(observation.entity_key),) + _present(
            attributes, ATTR_SOURCE_ENTITY_REF
        )
    if strategy is BlockingStrategy.NAME_LOCALITY:
        # One block per name token, paired with the locality. Keying on a
        # positional "surname" would assume a name ordering that does not hold
        # everywhere, and the full name under-blocks two spellings of one
        # person. Sharing any token in one locality is enough to be worth
        # scoring — over-blocking costs comparisons, under-blocking loses
        # matches outright.
        locality = attributes.get(ATTR_LOCALITY, "")
        tokens = attributes.get(ATTR_NAME, "").split()
        if not tokens or not locality:
            return ()
        return tuple(f"{token}|{locality}" for token in tokens)
    return ()


def _present(attributes: Mapping[str, str], attribute: str) -> tuple[str, ...]:
    value = attributes.get(attribute)
    return (value,) if value else ()


def _pairs(
    members: Sequence[EntityObservation],
) -> Iterable[tuple[EntityObservation, EntityObservation]]:
    """Ordered pairs within one block, each pair yielded once."""
    ordered = sorted(members, key=lambda observation: observation.observation_id)
    for index, left in enumerate(ordered):
        for right in ordered[index + 1 :]:
            yield left, right
