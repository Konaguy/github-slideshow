from phantom.deception import DeceptionPolicy, Honeypot


# -- the gate (charter §8, §9) ------------------------------------------


def test_deception_is_denied_by_default(tmp_path):
    """Nothing configured means nothing runs. This is the important one."""
    policy = DeceptionPolicy(tmp_path / "deception.json")
    decision = policy.evaluate()

    assert not decision.permitted
    assert len(decision.reasons) >= 3  # not enabled, no legal review, no jurisdiction


def test_enabling_without_clearing_a_jurisdiction_still_denies(tmp_path):
    """Opting in and clearing a jurisdiction are separate acts on purpose."""
    policy = DeceptionPolicy(tmp_path / "deception.json")
    policy.enable(jurisdiction="EXAMPLE-1", reviewed_by="counsel@example.com")

    decision = policy.evaluate()

    assert not decision.permitted
    assert any("allowlist" in r for r in decision.reasons)


def test_permitted_only_when_all_three_conditions_hold(tmp_path):
    policy = DeceptionPolicy(tmp_path / "deception.json")
    policy.enable(
        jurisdiction="EXAMPLE-1",
        reviewed_by="counsel@example.com",
        permitted_jurisdictions=["EXAMPLE-1"],
    )

    decision = policy.evaluate()

    assert decision.permitted, decision.summary()
    assert decision.reasons == []


def test_jurisdiction_outside_the_allowlist_is_denied(tmp_path):
    policy = DeceptionPolicy(tmp_path / "deception.json")
    policy.enable(
        jurisdiction="EXAMPLE-2",
        reviewed_by="counsel@example.com",
        permitted_jurisdictions=["EXAMPLE-1"],
    )

    decision = policy.evaluate()

    assert not decision.permitted
    assert any("EXAMPLE-2" in r for r in decision.reasons)


def test_disable_revokes_permission(tmp_path):
    policy = DeceptionPolicy(tmp_path / "deception.json")
    policy.enable(
        jurisdiction="EXAMPLE-1", reviewed_by="counsel@example.com",
        permitted_jurisdictions=["EXAMPLE-1"],
    )
    assert policy.evaluate().permitted

    policy.disable()

    assert not policy.evaluate().permitted


def test_legal_review_details_are_recorded_for_audit(tmp_path):
    policy = DeceptionPolicy(tmp_path / "deception.json")
    policy.enable(
        jurisdiction="EXAMPLE-1", reviewed_by="counsel@example.com",
        permitted_jurisdictions=["EXAMPLE-1"],
    )

    config = policy.load()

    assert config.legal_review_ack is True
    assert config.reviewed_by == "counsel@example.com"
    assert config.reviewed_at is not None


def test_config_survives_reload(tmp_path):
    """Separate CLI invocations must see the same opt-in state."""
    path = tmp_path / "deception.json"
    DeceptionPolicy(path).enable(
        jurisdiction="EXAMPLE-1", reviewed_by="counsel@example.com",
        permitted_jurisdictions=["EXAMPLE-1"],
    )

    assert DeceptionPolicy(path).evaluate().permitted


# -- the honeypot ---------------------------------------------------------


def test_migrate_clones_data_into_an_isolated_sandbox(tmp_path):
    source = tmp_path / "compromised"
    source.mkdir()
    (source / "notes.txt").write_text("user data")
    (source / "RANSOM_NOTE_README.txt").write_text("pay up")

    honeypot = Honeypot(tmp_path / "honeypot")
    session = honeypot.migrate(source, case_id="CASE-1")

    assert (session / "notes.txt").read_text() == "user data"
    assert (session / "RANSOM_NOTE_README.txt").read_text() == "pay up"
    assert honeypot.is_quarantined()


def test_harvest_records_hashes_not_contents(tmp_path):
    """TTP observations carry metadata only -- never the artifact bytes."""
    source = tmp_path / "compromised"
    source.mkdir()
    (source / "payload.bin").write_text("secret attacker tooling")

    honeypot = Honeypot(tmp_path / "honeypot")
    session = honeypot.migrate(source, case_id="CASE-1")
    observations = honeypot.harvest(session)

    assert len(observations) == 1
    assert observations[0].relpath == "payload.bin"
    assert observations[0].size_bytes == len("secret attacker tooling")
    assert "secret attacker tooling" not in honeypot.observations_path.read_text()


def test_harvested_hashes_are_publishable(tmp_path):
    source = tmp_path / "compromised"
    source.mkdir()
    (source / "a.bin").write_text("tool one")
    (source / "b.bin").write_text("tool two")

    honeypot = Honeypot(tmp_path / "honeypot")
    honeypot.harvest(honeypot.migrate(source, case_id="CASE-1"))

    assert len(honeypot.harvested_hashes()) == 2


def test_migrating_an_empty_instance_is_safe(tmp_path):
    honeypot = Honeypot(tmp_path / "honeypot")
    session = honeypot.migrate(tmp_path / "does-not-exist", case_id="CASE-1")

    assert session.exists()
    assert honeypot.harvest(session) == []
