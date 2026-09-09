"""End-to-end resolution over the synthetic datasets.

The scenarios these cover, using the CDR export and subscriber register as they
ship:

    CASE-001  SUB-SYNTH-0001 / REG-1001   one phone written two ways, plus IMEI,
                                          the operator reference and a
                                          consistent window -> auto-accepted
              SUB-SYNTH-0002 / REG-1002   two register entries on one household
              SUB-SYNTH-0002 / REG-1003   number, scoring alike -> both reviewed
              REG-1002 / REG-1003         one number, two identity references
    CASE-002  REG-2001 / REG-2002         a reassigned number -> conflict
              REG-2003 / REG-2004         similar names, one city, nothing else

Nothing in the data describes conduct; these are registration records whose
identifiers overlap the way real ones do.
"""
import json

import pytest

from app.core.audit.event_store import FlightRecorderEvent
from app.core.domain.case import Case
from app.core.evidence.models import TrustClassification
from app.core.evidence.service import EvidenceService
from app.core.graph.models import RelationshipType
from app.core.graph.service import GraphService
from app.core.resolution.policy import load_resolution_policy
from app.core.resolution.models import (
    DecidedBy,
    Recommendation,
    ReasonCode,
    ResolutionStatus,
    ReviewAction,
)
from app.core.resolution.service import (
    EntityResolutionService,
    ResolutionAccessDenied,
    ResolutionNotOpen,
)
from app.infrastructure.local_object_store import LocalFileEvidenceObjectStore
from app.infrastructure.sources.synthetic_cdr import SyntheticCDRSource
from app.infrastructure.sources.synthetic_subscriber import SyntheticSubscriberRegisterSource
from app.infrastructure.sqlite_evidence_repository import SQLiteEvidenceRepository
from app.infrastructure.sqlite_resolution_repository import SQLiteResolutionRepository
from tests.conftest import ANALYST, make_context, make_user
from tests.graph_fakes import InMemoryGraphRepository

CASE = Case(id="CASE-001", agency_id="POLICE", title="Resolution case", status="OPEN", security_level="L1")
OTHER_CASE = Case(
    id="CASE-002", agency_id="POLICE", title="Second case", status="OPEN", security_level="L1"
)

# L3 clears the privacy policy's unmask minimum, so a reader at this level sees
# unmasked labels and the masking tests can vary clearance deliberately.
READER = "USR-104"


@pytest.fixture
def wiring(tmp_path, security, grants, policy, event_store):
    evidence_repo = SQLiteEvidenceRepository(tmp_path / "investigation.db")
    resolution_repo = SQLiteResolutionRepository(tmp_path / "investigation.db")
    objects = LocalFileEvidenceObjectStore(tmp_path / "objects")
    graph = InMemoryGraphRepository()

    evidence = EvidenceService(
        repository=evidence_repo,
        object_store=objects,
        security=security,
        event_store=event_store,
        privacy=policy.privacy,
    )
    resolution = EntityResolutionService(
        resolution_repository=resolution_repo,
        evidence_repository=evidence_repo,
        object_store=objects,
        graph_repository=graph,
        security=security,
        event_store=event_store,
        policy=load_resolution_policy(),
        privacy=policy.privacy,
    )

    grants.grant_agency(READER, "POLICE")
    for case in (CASE, OTHER_CASE):
        grants.grant_case(READER, "POLICE", case.id, need_to_know=True)
        evidence.ingest_from_source(case, SyntheticCDRSource())
        evidence.ingest_from_source(case, SyntheticSubscriberRegisterSource())

    yield {
        "evidence": evidence,
        "resolution": resolution,
        "evidence_repo": evidence_repo,
        "resolution_repo": resolution_repo,
        "objects": objects,
        "graph": graph,
    }
    evidence_repo.close()
    resolution_repo.close()


@pytest.fixture
def service(wiring):
    return wiring["resolution"]


@pytest.fixture
def graph(wiring):
    return wiring["graph"]


def run(service, case=CASE, level="L3"):
    return service.run(make_user(READER, level=level), make_context(READER, level=level), case)


def decisions_by_pair(service, case=CASE, level="L3"):
    views = service.list_resolutions(
        make_user(READER, level=level), make_context(READER, level=level), case
    )
    return {
        frozenset((view.decision.left.entity_key, view.decision.right.entity_key)): view
        for view in views
    }


def pair(service, left, right, case=CASE):
    return decisions_by_pair(service, case)[frozenset((left, right))]


# -- the run ----------------------------------------------------------------


def test_a_run_reports_what_it_did(service):
    summary = run(service)

    assert summary.case_id == CASE.id
    assert summary.evidence_considered == 3  # two CDR exports and one register
    assert summary.observations == 5
    assert summary.candidates == 4
    assert summary.policy_version == load_resolution_policy().policy_version


def test_resolution_never_runs_as_a_side_effect_of_reading(service, wiring):
    """Listing resolutions before any run finds nothing and creates nothing."""
    views = service.list_resolutions(make_user(READER), make_context(READER), CASE)

    assert views == []
    assert wiring["resolution_repo"].list_candidates(CASE.id) == []


def test_ingestion_does_not_resolve_anything(wiring):
    """Evidence ingestion is untouched by resolution; the step is explicit."""
    assert wiring["resolution_repo"].list_decisions(CASE.id) == []


# -- scenario A/B/C: one entity across two sources --------------------------


def test_an_exact_identifier_match_across_two_evidence_items_is_accepted(service):
    run(service)

    view = pair(service, "SUB-SYNTH-0001", "REG-1001")

    assert view.decision.status is ResolutionStatus.AUTO_ACCEPTED
    assert view.decision.score.recommendation is Recommendation.MATCH
    assert view.decision.left.evidence_id != view.decision.right.evidence_id


def test_formatting_only_variation_resolves_deterministically(service, wiring):
    """The CDR wrote `+919876543210`; the register wrote `+91 98765 43210`."""
    run(service)
    view = pair(service, "SUB-SYNTH-0001", "REG-1001")

    raw_values = json.dumps(
        [
            json.loads(
                wiring["objects"].get(
                    wiring["evidence_repo"].get_latest_version(ref.evidence_id).payload_ref
                )
            )
            for ref in (view.decision.left, view.decision.right)
        ]
    )

    assert "+919876543210" in raw_values and "+91 98765 43210" in raw_values
    assert ReasonCode.EXACT_PHONE_MATCH in view.decision.score.reasons


def test_a_strong_multi_signal_match_carries_every_supporting_signal(service):
    run(service)

    score = pair(service, "SUB-SYNTH-0001", "REG-1001").decision.score

    assert {
        ReasonCode.EXACT_PHONE_MATCH,
        ReasonCode.EXACT_IMEI_MATCH,
        ReasonCode.SOURCE_IDENTIFIER_MATCH,
        ReasonCode.TEMPORAL_CONSISTENT,
        ReasonCode.CROSS_SOURCE_AGREEMENT,
    } <= set(score.reasons)
    assert score.conflicts == ()


def test_an_automated_acceptance_is_recorded_as_automated(service):
    run(service)

    decision = pair(service, "SUB-SYNTH-0001", "REG-1001").decision

    assert decision.decision_actor is DecidedBy.SYSTEM
    assert decision.decided_by == DecidedBy.SYSTEM.value
    assert decision.decided_at is not None


# -- scenario D: ambiguity ---------------------------------------------------


def test_two_candidates_scoring_alike_both_go_to_review(service):
    """REG-1002 and REG-1003 are equally good matches for one CDR subscriber."""
    run(service)

    first = pair(service, "SUB-SYNTH-0002", "REG-1002").decision
    second = pair(service, "SUB-SYNTH-0002", "REG-1003").decision

    assert abs(first.score.score - second.score.score) <= 0.05
    assert first.status is second.status is ResolutionStatus.REVIEW_REQUIRED
    assert ReasonCode.AMBIGUOUS_ALTERNATIVE in first.score.reasons
    assert ReasonCode.AMBIGUOUS_ALTERNATIVE in second.score.reasons


def test_an_ambiguous_pair_is_not_merged_despite_a_high_score(service, graph):
    run(service)

    decision = pair(service, "SUB-SYNTH-0002", "REG-1002").decision

    assert decision.score.score > 0.9
    assert decision.score.recommendation is Recommendation.REVIEW_REQUIRED
    linked = {
        link.properties["resolution_id"] for link in graph.fetch_inferred_links(CASE.id)
    }
    assert decision.resolution_id not in linked


# -- scenario E: conflict ----------------------------------------------------


def test_conflicting_identity_references_do_not_auto_merge(service):
    """A reassigned number: the identifiers agree, the identity references do not."""
    run(service, OTHER_CASE)

    decision = pair(service, "REG-2001", "REG-2002", OTHER_CASE).decision

    assert decision.status is ResolutionStatus.REVIEW_REQUIRED
    assert decision.score.recommendation is Recommendation.CONFLICT
    assert decision.score.blocks_auto_accept
    assert "national_id_ref" in {c.attribute for c in decision.score.conflicts}


def test_a_conflicting_pair_is_surfaced_not_dropped(service):
    run(service, OTHER_CASE)

    view = pair(service, "REG-2001", "REG-2002", OTHER_CASE)

    assert view.decision.is_open  # it reaches a person rather than disappearing


# -- scenario F: distinct entities -------------------------------------------


def test_similar_names_in_one_city_stay_separate(service, graph):
    run(service, OTHER_CASE)

    decision = pair(service, "REG-2003", "REG-2004", OTHER_CASE).decision

    assert decision.status is ResolutionStatus.CANDIDATE
    assert decision.score.recommendation is Recommendation.UNRESOLVED
    assert graph.fetch_inferred_links(OTHER_CASE.id) == ()


def test_an_unresolved_pair_is_still_recorded(service):
    """The system keeps the record that it considered them and did not merge them."""
    run(service, OTHER_CASE)

    view = pair(service, "REG-2003", "REG-2004", OTHER_CASE)

    assert view.candidate is not None
    assert view.candidate.blocking_strategy.value == "NAME_LOCALITY"


# -- scenario G: idempotency -------------------------------------------------


def test_re_running_over_unchanged_evidence_changes_nothing(service, wiring):
    first = run(service)
    before = wiring["resolution_repo"].list_decisions(CASE.id)

    second = run(service)
    after = wiring["resolution_repo"].list_decisions(CASE.id)

    assert second.unchanged == first.candidates
    assert second.auto_accepted == second.review_required == second.unresolved == 0
    assert [d.resolution_id for d in after] == [d.resolution_id for d in before]
    assert [d.status for d in after] == [d.status for d in before]


def test_re_running_does_not_duplicate_inferred_links(service, graph):
    run(service)
    once = len(graph.fetch_inferred_links(CASE.id))

    run(service)

    assert len(graph.fetch_inferred_links(CASE.id)) == once == 1


def test_resolution_ids_are_deterministic(service, wiring):
    run(service)

    ids = [d.resolution_id for d in wiring["resolution_repo"].list_decisions(CASE.id)]

    assert all("-v1" in resolution_id for resolution_id in ids)
    assert len(set(ids)) == len(ids)


# -- scenario H: new evidence ------------------------------------------------


def new_register(tmp_path, case_id, register_id, subscribers):
    path = tmp_path / f"{register_id}.json"
    path.write_text(
        json.dumps(
            {
                "dataset": "SYNTHETIC-EXTRA",
                "registers": [
                    {
                        "register_id": register_id,
                        "registrar": "SYNTH-TELECOM",
                        "case_id": case_id,
                        "subscribers": subscribers,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return SyntheticSubscriberRegisterSource(path)


def test_new_evidence_adds_a_candidate_without_deleting_earlier_decisions(
    service, wiring, tmp_path
):
    run(service)
    before = {d.resolution_id for d in wiring["resolution_repo"].list_decisions(CASE.id)}

    wiring["evidence"].ingest_from_source(
        CASE,
        new_register(
            tmp_path,
            CASE.id,
            "REG-EXPORT-LATE",
            [
                {
                    "register_id": "REG-1009",
                    "subscriber_name": "Ananya Sharma",
                    "subscriber_address": "12 M.G. Road, Pune",
                    "locality": "Pune",
                    "msisdn": "919876543210",
                    "account_number": "ACC-88213",
                    "registered_at": "2026-02-05T00:00:00+05:30",
                }
            ],
        ),
    )
    summary = run(service)

    after = {d.resolution_id for d in wiring["resolution_repo"].list_decisions(CASE.id)}
    assert before <= after
    assert summary.candidates > len(before)


def test_a_changed_evidence_version_supersedes_without_losing_history(
    service, wiring, tmp_path
):
    """A corrected register row is a new version, so the decision is re-made."""
    source = new_register(
        tmp_path,
        OTHER_CASE.id,
        "REG-EXPORT-002",  # same source record id as the shipped register
        [
            {
                "register_id": "REG-2001",
                "subscriber_name": "Vikram Rao",
                "subscriber_address": "5 Baner Road, Pune",
                "locality": "Pune",
                "msisdn": "+91 98450 00111",
                "imei": "351756051523999",
                "account_number": "ACC-31002",
                "national_id_ref": "NID-SYNTH-A1",
                "registered_at": "2024-03-02T00:00:00+05:30",
                "valid_until": "2025-12-31T00:00:00+05:30",
            },
            {
                "register_id": "REG-2002",
                "subscriber_name": "Deepa Nair",
                "subscriber_address": "77 Kothrud Lane, Pune",
                "locality": "Pune",
                "msisdn": "919845000111",
                "imei": "351756051523999",
                "account_number": "ACC-44988",
                "national_id_ref": "NID-SYNTH-B2",
                "registered_at": "2026-01-20T00:00:00+05:30",
            },
        ],
    )
    run(service, OTHER_CASE)
    original = pair(service, "REG-2001", "REG-2002", OTHER_CASE).decision

    wiring["evidence"].ingest_from_source(OTHER_CASE, source)
    summary = run(service, OTHER_CASE)

    lineage = wiring["resolution_repo"].list_lineage(original.lineage_id)
    assert summary.superseded >= 1
    assert len(lineage) == 2
    assert lineage[0].status is ResolutionStatus.SUPERSEDED
    assert lineage[0].superseded_by == lineage[1].resolution_id
    assert lineage[1].resolution_version == 2
    assert ReasonCode.SUPERSEDED_BY_NEW_EVIDENCE in lineage[1].score.reasons


# -- review workflow ---------------------------------------------------------


def open_resolution(service, case=CASE):
    run(service, case)
    return next(
        view.decision
        for view in service.list_resolutions(make_user(READER), make_context(READER), case)
        if view.decision.is_open
    )


def test_approving_records_a_human_decision(service):
    decision = open_resolution(service)

    view = service.review(
        make_user(READER),
        make_context(READER),
        CASE,
        decision.resolution_id,
        ReviewAction.APPROVE,
        reason="verified against the register",
    )

    assert view.decision.status is ResolutionStatus.APPROVED
    assert view.decision.decision_actor is DecidedBy.HUMAN
    assert view.decision.decided_by == READER
    assert view.decision.decided_at is not None
    assert view.decision.decision_reason == "verified against the register"


def test_rejecting_records_a_human_decision(service):
    decision = open_resolution(service)

    view = service.review(
        make_user(READER), make_context(READER), CASE, decision.resolution_id, ReviewAction.REJECT
    )

    assert view.decision.status is ResolutionStatus.REJECTED
    assert view.decision.decision_actor is DecidedBy.HUMAN


def test_deferring_leaves_the_resolution_open_and_recorded(service):
    decision = open_resolution(service)

    view = service.review(
        make_user(READER),
        make_context(READER),
        CASE,
        decision.resolution_id,
        ReviewAction.DEFER,
        reason="waiting on the register response",
    )

    assert view.decision.status is ResolutionStatus.REVIEW_REQUIRED
    assert [review.action for review in view.reviews] == [ReviewAction.DEFER]
    assert view.reviews[0].reviewer_id == READER


def test_review_history_is_append_only(service):
    decision = open_resolution(service)
    user, context = make_user(READER), make_context(READER)

    service.review(user, context, CASE, decision.resolution_id, ReviewAction.DEFER, "later")
    view = service.review(user, context, CASE, decision.resolution_id, ReviewAction.APPROVE)

    assert [review.action for review in view.reviews] == [
        ReviewAction.DEFER,
        ReviewAction.APPROVE,
    ]


def test_a_decided_resolution_cannot_be_decided_again(service):
    decision = open_resolution(service)
    user, context = make_user(READER), make_context(READER)
    service.review(user, context, CASE, decision.resolution_id, ReviewAction.APPROVE)

    with pytest.raises(ResolutionNotOpen):
        service.review(user, context, CASE, decision.resolution_id, ReviewAction.REJECT)


def test_an_automated_acceptance_is_not_open_to_review(service):
    run(service)
    auto = pair(service, "SUB-SYNTH-0001", "REG-1001").decision

    with pytest.raises(ResolutionNotOpen):
        service.review(
            make_user(READER), make_context(READER), CASE, auto.resolution_id, ReviewAction.APPROVE
        )


def test_a_role_without_the_review_permission_cannot_decide(service):
    decision = open_resolution(service)
    analyst = make_user(READER)
    context = make_context(READER, role=ANALYST)

    with pytest.raises(ResolutionAccessDenied):
        service.review(analyst, context, CASE, decision.resolution_id, ReviewAction.APPROVE)


def test_a_rejected_resolution_is_not_re_accepted_by_a_later_run(
    service, wiring, tmp_path
):
    """New evidence may change the score; it does not overturn a person's call."""
    run(service, OTHER_CASE)
    decision = pair(service, "REG-2001", "REG-2002", OTHER_CASE).decision
    service.review(
        make_user(READER),
        make_context(READER),
        OTHER_CASE,
        decision.resolution_id,
        ReviewAction.REJECT,
        reason="different registrants",
    )

    wiring["evidence"].ingest_from_source(
        OTHER_CASE,
        new_register(
            tmp_path,
            OTHER_CASE.id,
            "REG-EXPORT-002",
            [
                {
                    "register_id": "REG-2001",
                    "subscriber_name": "Vikram Rao",
                    "locality": "Pune",
                    "msisdn": "+91 98450 00111",
                    "imei": "351756051523999",
                    "registered_at": "2026-01-19T00:00:00+05:30",
                },
                {
                    "register_id": "REG-2002",
                    "subscriber_name": "Vikram Rao",
                    "locality": "Pune",
                    "msisdn": "919845000111",
                    "imei": "351756051523999",
                    "registered_at": "2026-01-20T00:00:00+05:30",
                },
            ],
        ),
    )
    run(service, OTHER_CASE)

    lineage = wiring["resolution_repo"].list_lineage(decision.lineage_id)
    assert lineage[-1].status is ResolutionStatus.REVIEW_REQUIRED
    assert ReasonCode.PRIOR_HUMAN_REJECTION in lineage[-1].score.reasons


# -- graph projection --------------------------------------------------------


def test_an_accepted_resolution_writes_an_inferred_link(service, graph):
    run(service)

    links = graph.fetch_inferred_links(CASE.id)

    assert len(links) == 1
    assert links[0].type is RelationshipType.INFERRED_SAME_ENTITY
    assert links[0].properties["trust_class"] == TrustClassification.INFERRED.value


def test_an_inferred_link_carries_its_provenance(service, graph):
    run(service)
    decision = pair(service, "SUB-SYNTH-0001", "REG-1001").decision

    link = graph.fetch_inferred_links(CASE.id)[0]

    assert link.properties["resolution_id"] == decision.resolution_id
    assert link.properties["policy_version"] == decision.policy_version
    assert link.properties["confidence"] == decision.score.confidence.value
    assert len(link.properties["source_evidence_version_ids"]) == 2
    assert "EXACT_PHONE" in link.properties["supporting_signals"]


def test_observed_relationships_are_untouched_by_resolution(
    wiring, service, security, event_store, policy
):
    """Ingesting the graph and then resolving leaves every observation as it was."""
    graph_service = GraphService(
        graph_repository=wiring["graph"],
        evidence_repository=wiring["evidence_repo"],
        object_store=wiring["objects"],
        security=security,
        event_store=event_store,
        privacy=policy.privacy,
    )
    graph_service.ingest_case_evidence(CASE)
    observed_before = {
        observation_id: relationship.properties
        for observation_id, relationship in wiring["graph"].relationships.items()
    }

    run(service)

    for observation_id, properties in observed_before.items():
        assert wiring["graph"].relationships[observation_id].properties == properties


def test_an_inferred_link_is_never_returned_as_an_observation(
    wiring, service, security, event_store, policy
):
    graph_service = GraphService(
        graph_repository=wiring["graph"],
        evidence_repository=wiring["evidence_repo"],
        object_store=wiring["objects"],
        security=security,
        event_store=event_store,
        privacy=policy.privacy,
    )
    graph_service.ingest_case_evidence(CASE)
    run(service)

    authorized = graph_service.get_case_graph(
        make_user(READER, level="L3"), make_context(READER, level="L3"), CASE
    )

    assert all(
        relationship.type is not RelationshipType.INFERRED_SAME_ENTITY
        for relationship in authorized.relationships
    )


def test_approving_writes_the_link_and_rejecting_writes_none(service, graph):
    run(service)
    approved = pair(service, "SUB-SYNTH-0002", "REG-1002").decision
    rejected = pair(service, "SUB-SYNTH-0002", "REG-1003").decision
    user, context = make_user(READER), make_context(READER)

    service.review(user, context, CASE, approved.resolution_id, ReviewAction.APPROVE)
    service.review(user, context, CASE, rejected.resolution_id, ReviewAction.REJECT)

    assert graph.fetch_inferred_links(CASE.id, [approved.resolution_id])
    assert graph.fetch_inferred_links(CASE.id, [rejected.resolution_id]) == ()


def test_superseding_an_approved_resolution_restates_its_link(
    service, graph, wiring, tmp_path
):
    """The graph keeps the record that this identity was once inferred."""
    run(service, OTHER_CASE)
    decision = pair(service, "REG-2001", "REG-2002", OTHER_CASE).decision
    service.review(
        make_user(READER),
        make_context(READER),
        OTHER_CASE,
        decision.resolution_id,
        ReviewAction.APPROVE,
    )
    assert graph.fetch_inferred_links(OTHER_CASE.id, [decision.resolution_id])

    wiring["evidence"].ingest_from_source(
        OTHER_CASE,
        new_register(
            tmp_path,
            OTHER_CASE.id,
            "REG-EXPORT-002",
            [
                {
                    "register_id": "REG-2001",
                    "subscriber_name": "Vikram Rao",
                    "locality": "Pune",
                    "msisdn": "+91 98450 00111",
                    "registered_at": "2026-01-19T00:00:00+05:30",
                },
                {
                    "register_id": "REG-2002",
                    "subscriber_name": "Deepa Nair",
                    "locality": "Pune",
                    "msisdn": "919845000111",
                    "registered_at": "2026-01-20T00:00:00+05:30",
                },
            ],
        ),
    )
    run(service, OTHER_CASE)

    link = graph.fetch_inferred_links(OTHER_CASE.id, [decision.resolution_id])[0]
    assert link.properties["status"] == ResolutionStatus.SUPERSEDED.value
    assert link.properties["status_updated_at"]


def test_a_graph_outage_does_not_lose_the_decisions(service, graph, wiring):
    graph._available = False

    summary = run(service)

    assert summary.graph_available is False
    assert summary.links_projected == 0
    assert summary.auto_accepted == 1
    assert wiring["resolution_repo"].list_decisions(CASE.id)


def test_projection_catches_up_once_the_graph_returns(service, graph):
    graph._available = False
    run(service)

    graph._available = True
    summary = run(service)

    assert summary.unchanged == summary.candidates  # nothing re-decided
    assert summary.links_projected == 1


# -- authorization -----------------------------------------------------------


def test_a_reader_without_the_case_is_denied(service, grants):
    grants.revoke_case(READER, "POLICE", CASE.id)

    with pytest.raises(ResolutionAccessDenied):
        run(service)


def test_a_denial_carries_no_resolution_data(service, grants):
    run(service)
    grants.revoke_case(READER, "POLICE", CASE.id)

    with pytest.raises(ResolutionAccessDenied) as denied:
        service.list_resolutions(make_user(READER), make_context(READER), CASE)

    assert "REG-" not in str(denied.value)
    assert "9198" not in str(denied.value)


def test_resolutions_are_scoped_to_their_case(service):
    run(service)
    run(service, OTHER_CASE)

    first = decisions_by_pair(service, CASE)
    second = decisions_by_pair(service, OTHER_CASE)

    assert frozenset(("REG-2001", "REG-2002")) not in first
    assert frozenset(("SUB-SYNTH-0001", "REG-1001")) not in second
    assert all(view.decision.case_id == CASE.id for view in first.values())


def test_a_resolution_from_another_case_cannot_be_read_through_this_one(service):
    run(service, OTHER_CASE)
    foreign = next(iter(decisions_by_pair(service, OTHER_CASE).values())).decision

    with pytest.raises(Exception) as raised:
        service.get_resolution(
            make_user(READER), make_context(READER), CASE, foreign.resolution_id
        )

    assert raised.type.__name__ in {"ResolutionNotFound", "ResolutionAccessDenied"}


def test_evidence_the_reader_may_not_see_never_enters_the_comparison(service, wiring):
    """An unauthorized evidence item contributes no observation and no candidate."""
    high = wiring["evidence_repo"].list_evidence_for_case(CASE.id)[0]
    wiring["evidence_repo"]._execute(
        "UPDATE evidence SET security_level = ? WHERE evidence_id = ?", ("L3", high.id)
    )

    summary = run(service, level="L2")

    assert summary.evidence_excluded == 1
    assert summary.evidence_considered == 2
    assert all(
        high.id not in (d.left.evidence_id, d.right.evidence_id)
        for d in wiring["resolution_repo"].list_decisions(CASE.id)
    )


def test_a_partial_reader_gets_masked_labels(service):
    run(service, level="L3")

    views = service.list_resolutions(
        make_user(READER, level="L2"), make_context(READER, level="L2"), CASE
    )

    assert views
    assert all("REG-" not in view.left_label for view in views)
    assert all("REG-" not in view.right_label for view in views)
    assert all("entity_key" in view.masked_fields for view in views)


def test_a_cleared_reader_sees_unmasked_labels(service):
    run(service, level="L3")

    views = service.list_resolutions(
        make_user(READER, level="L3"), make_context(READER, level="L3"), CASE
    )

    assert any("REG-" in view.left_label or "REG-" in view.right_label for view in views)
    assert all(view.masked_fields == () for view in views)


# -- audit -------------------------------------------------------------------


def test_a_run_is_audited_end_to_end(service, event_store):
    run(service)

    def types(event_type):
        return [
            event
            for event in event_store.list_by_type(event_type)
            if event.case_id == CASE.id
        ]

    assert len(types(FlightRecorderEvent.ENTITY_RESOLUTION_STARTED)) == 1
    assert len(types(FlightRecorderEvent.ENTITY_RESOLUTION_COMPLETED)) == 1
    assert len(types(FlightRecorderEvent.ENTITY_RESOLUTION_CANDIDATE_CREATED)) == 4
    assert len(types(FlightRecorderEvent.ENTITY_RESOLUTION_AUTO_ACCEPTED)) == 1
    assert len(types(FlightRecorderEvent.ENTITY_RESOLUTION_REVIEW_REQUIRED)) == 3
    assert len(types(FlightRecorderEvent.ENTITY_RESOLUTION_PROJECTED)) == 1


def test_audit_payloads_explain_the_outcome_without_the_data(service, event_store):
    run(service)

    accepted = event_store.list_by_type(FlightRecorderEvent.ENTITY_RESOLUTION_AUTO_ACCEPTED)[0]

    assert accepted.actor_id == READER
    assert accepted.case_id == CASE.id
    assert accepted.payload["policy_version"] == load_resolution_policy().policy_version
    assert "EXACT_PHONE_MATCH" in accepted.payload["reasons"]
    assert "919876543210" not in json.dumps(dict(accepted.payload))


def test_human_decisions_are_audited_separately_from_automated_ones(service, event_store):
    decision = open_resolution(service)

    service.review(
        make_user(READER), make_context(READER), CASE, decision.resolution_id, ReviewAction.APPROVE
    )

    approved = event_store.list_by_type(FlightRecorderEvent.ENTITY_RESOLUTION_APPROVED)
    assert len(approved) == 1
    assert approved[0].payload["decision_actor"] == DecidedBy.HUMAN.value
    assert approved[0].payload["reviewer_id"] == READER


def test_supersession_is_audited(service, wiring, tmp_path, event_store):
    run(service, OTHER_CASE)
    wiring["evidence"].ingest_from_source(
        OTHER_CASE,
        new_register(
            tmp_path,
            OTHER_CASE.id,
            "REG-EXPORT-002",
            [
                {
                    "register_id": "REG-2001",
                    "subscriber_name": "Vikram Rao",
                    "locality": "Pune",
                    "msisdn": "+91 98450 00111",
                    "registered_at": "2026-01-19T00:00:00+05:30",
                },
                {
                    "register_id": "REG-2002",
                    "subscriber_name": "Deepa Nair",
                    "locality": "Pune",
                    "msisdn": "919845000111",
                    "registered_at": "2026-01-20T00:00:00+05:30",
                },
            ],
        ),
    )
    run(service, OTHER_CASE)

    superseded = [
        event
        for event in event_store.list_by_type(FlightRecorderEvent.ENTITY_RESOLUTION_SUPERSEDED)
        if event.case_id == OTHER_CASE.id
    ]
    assert superseded
    assert superseded[0].payload["superseded_by"].endswith("-v2")


def test_a_denied_run_is_audited(service, event_store, grants):
    grants.revoke_case(READER, "POLICE", CASE.id)

    with pytest.raises(ResolutionAccessDenied):
        run(service)

    denied = event_store.list_by_type(FlightRecorderEvent.ENTITY_RESOLUTION_ACCESS_DENIED)
    assert denied
    assert denied[0].payload["scope"] == "CASE"
