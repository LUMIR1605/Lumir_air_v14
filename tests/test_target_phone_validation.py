from osint_lab.agents import PhoneMatchLevel, TargetPhoneValidator, generate_phone_variants
from osint_lab.agents.phone_public_parsers import parse_target_page


PHONE = "+48123456789"
VARIANTS = generate_phone_variants(PHONE)


def validate(body, *, url="https://company.test/contact"):
    page = parse_target_page(body=body, final_url=url)
    return TargetPhoneValidator().validate(page, VARIANTS)


def test_tel_link_is_structured_match():
    value = validate('<html><body><a href="tel:+48123456789">Call</a></body></html>')
    assert value.level is PhoneMatchLevel.STRUCTURED_PHONE_MATCH
    assert value.signal_type == "TEL_LINK"
    assert value.signal_path == "structured:tel_href"


def test_schema_telephone_is_structured_match():
    value = validate('<html><body><span itemprop="telephone">123 456 789</span></body></html>')
    assert value.level is PhoneMatchLevel.STRUCTURED_PHONE_MATCH
    assert value.signal_type == "SCHEMA_TELEPHONE"


def test_json_ld_telephone_is_structured_match():
    value = validate(
        '<script type="application/ld+json">'
        '{"@type":"Organization","telephone":"+48 123 456 789"}</script>'
    )
    assert value.level is PhoneMatchLevel.STRUCTURED_PHONE_MATCH
    assert value.signal_type == "JSON_LD_TELEPHONE"


def test_visible_telephone_context_preserves_small_context_window():
    value = validate(
        "<p>Kontakt: Fixture Company, tel. 123 456 789, biuro@example.test</p>"
    )
    assert value.level is PhoneMatchLevel.PHONE_CONTEXT_MATCH
    assert value.context_before
    assert value.matched_text == "123 456 789"
    assert value.context_after
    assert value.normalized_phone == PHONE


def test_visible_contact_context_is_accepted():
    assert validate("<p>Kontakt: 123456789</p>").level is PhoneMatchLevel.PHONE_CONTEXT_MATCH


def test_generic_numeric_token_is_not_accepted():
    value = validate("<p>Public reference 123456789 in unrelated text.</p>")
    assert value.level is PhoneMatchLevel.NUMERIC_MATCH_ONLY
    assert value.accepted is False


def test_product_id_is_rejected():
    assert validate("<p>Product ID: 123456789</p>").level is PhoneMatchLevel.REJECTED_NUMERIC_ID


def test_image_id_is_rejected():
    value = validate(
        "<p>Royalty-free stock image.</p>",
        url="https://stock-images.test/image-photo/synthetic-fixture-123456789",
    )
    assert value.level is PhoneMatchLevel.REJECTED_NUMERIC_ID


def test_article_id_is_rejected():
    assert validate("<p>Article ID: 123456789</p>").level is PhoneMatchLevel.REJECTED_NUMERIC_ID


def test_url_only_phone_digits_are_rejected():
    value = validate("<p>No telephone here.</p>", url="https://public.test/resource/123456789")
    assert value.level is PhoneMatchLevel.REJECTED_NUMERIC_ID


def test_0048_and_local_format_are_normalized_equivalently():
    international = validate("<p>Telefon: 0048 123 456 789</p>")
    local = validate("<p>Telefon: 123-456-789</p>")
    assert international.level is PhoneMatchLevel.PHONE_CONTEXT_MATCH
    assert local.level is PhoneMatchLevel.PHONE_CONTEXT_MATCH
    assert international.normalized_phone == local.normalized_phone == PHONE
