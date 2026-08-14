import importlib.util
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "securityhub_collect", Path(__file__).with_name("securityhub_collect.py")
)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class FakeClient:
    class exceptions:
        ResourceNotFoundException = type("ResourceNotFoundException", (Exception,), {})

    def __init__(self, pages):
        self.pages = iter(pages)
        self.requests = []

    def get_findings(self, **request):
        self.requests.append(request)
        return next(self.pages)


def finding(identifier="finding-1", remediation=None):
    value = {"Id": identifier, "Title": "Example", "Resources": []}
    if remediation is not None:
        value["Remediation"] = remediation
    return value


def test_collect_findings_paginates_and_applies_filters():
    client = FakeClient(
        [
            {"Findings": [finding()], "NextToken": "next"},
            {"Findings": [finding("finding-2")]},
        ]
    )
    results = module.collect_findings(client, "123", "us-east-1", {"HIGH"}, {"NEW"})
    assert [item["id"] for item in results] == ["finding-1", "finding-2"]
    assert client.requests[0]["Filters"] == {
        "SeverityLabel": [{"Value": "HIGH", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
    }
    assert client.requests[1]["NextToken"] == "next"


def test_normalize_handles_missing_and_null_remediation():
    assert (
        module.normalize_finding(finding(), "123", "us-east-1")["remediation"] is None
    )
    assert (
        module.normalize_finding(finding("2", None), "123", "us-east-1")["remediation"]
        is None
    )
    assert (
        module.normalize_finding(
            finding("3", {"Recommendation": None}), "123", "us-east-1"
        )["remediation"]
        is None
    )


def test_finding_key_is_collision_safe_and_stable():
    first = finding("a|b")
    second = finding("a", {"Recommendation": {"Text": "b"}})
    key1 = module._finding_key(first, "account|1", "region")
    key2 = module._finding_key(second, "account", "1|region")
    assert key1 != key2
    assert key1 == module._finding_key(first, "account|1", "region")
