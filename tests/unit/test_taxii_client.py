import json
import urllib.error

from src.reporting.taxii_client import (
    TaxiiPushConfig,
    prepare_taxii_envelope,
    push_stix_bundle,
)


def _bundle() -> dict:
    return {
        "type": "bundle",
        "id": "bundle--11111111-1111-4111-8111-111111111111",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--22222222-2222-4222-8222-222222222222",
                "pattern": "[domain-name:value = 'example.test']",
                "pattern_type": "stix",
                "valid_from": "2026-05-15T00:00:00Z",
            }
        ],
    }


def test_prepare_taxii_envelope_sends_objects_not_bundle_wrapper():
    envelope = prepare_taxii_envelope(json.dumps(_bundle()))

    assert set(envelope) == {"objects"}
    assert envelope["objects"][0]["type"] == "indicator"
    assert "bundle" not in json.dumps(envelope)


def test_taxii_push_posts_envelope_and_redacts_target():
    captured = {}

    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    def opener(request, timeout, context):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        captured["auth"] = request.get_header("Authorization")
        captured["content_type"] = request.get_header("Content-type")
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return Response()

    config = TaxiiPushConfig(
        enabled=True,
        objects_url="https://user:pass@taxii.example.test/api/collections/demo/objects/?token=secret",
        bearer_token="secret-bearer",
        timeout_seconds=3,
    )

    result = push_stix_bundle(_bundle(), config=config, opener=opener)

    assert result.success
    assert result.status == "success"
    assert result.target == "https://taxii.example.test/api/collections/demo/objects/"
    assert result.object_count == 1
    assert captured["timeout"] == 3
    assert captured["auth"] == "Bearer secret-bearer"
    assert captured["content_type"] == "application/taxii+json;version=2.1"
    assert captured["body"] == {"objects": _bundle()["objects"]}
    assert "secret-bearer" not in str(result.to_dict())
    assert "token=secret" not in str(result.to_dict())


def test_taxii_push_disabled_is_safe_skip():
    result = push_stix_bundle(_bundle(), config=TaxiiPushConfig(enabled=False))

    assert result.success
    assert result.status == "skipped"
    assert result.enabled is False


def test_taxii_push_http_error_does_not_echo_credentials():
    def opener(request, timeout, context):
        raise urllib.error.HTTPError(
            request.full_url,
            401,
            "Unauthorized",
            hdrs=None,
            fp=None,
        )

    config = TaxiiPushConfig(
        enabled=True,
        objects_url="https://user:password@taxii.example.test/collections/demo/objects/?token=secret",
        username="user",
        password="password",
    )

    result = push_stix_bundle(_bundle(), config=config, opener=opener)

    assert not result.success
    assert result.status == "failed"
    assert result.http_status == 401
    serialized = str(result.to_dict())
    assert "password" not in serialized
    assert "token=secret" not in serialized
