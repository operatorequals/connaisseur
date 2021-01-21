import os
import pytest
from flask import Flask
import json
from connaisseur.image import Image
from connaisseur.exceptions import NotFoundException
import connaisseur.flask_server as fs
import connaisseur.policy as policy
import connaisseur.kube_api as api
import connaisseur.mutate as mutate
from requests.exceptions import HTTPError
from connaisseur.config import Config, Notary

sample_config = [
    {
        "name": "dockerhub",
        "host": "notary.docker.io",
        "rootKeys": [
            {
                "name": "alice",
                "key": (
                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtR5kwrDK22SyCu7WMF8tCjVgeORA"
                    "S2PWacRcBN/VQdVK4PVk1w4pMWlz9AHQthDGl+W2k3elHkPbR+gNkK2PCA=="
                ),
            }
        ],
        "isAcr": False,
        "hasAuth": True,
        "auth": {"USER": "bert", "PASS": "bertig"},
        "isSelfsigned": False,
        "selfsignedCert": None,
    }
]


@pytest.fixture
def mock_kube_request(monkeypatch):
    def m_request(path: str):
        name = path.split("/")[-1]
        try:
            return get_file_json(f"tests/data/{name}.json")
        except FileNotFoundError:
            raise HTTPError

    monkeypatch.setattr(api, "request_kube_api", m_request)


@pytest.fixture
def mock_policy_no_verify(monkeypatch):
    def m__init__(self):
        self.policy = {"rules": [{"pattern": "*:*", "verify": False}]}

    monkeypatch.setattr(policy.ImagePolicy, "__init__", m__init__)


@pytest.fixture
def mock_policy_verify(monkeypatch):
    def m__init__(self):
        self.policy = {"rules": [{"pattern": "*:*", "verify": True}]}

    monkeypatch.setattr(policy.ImagePolicy, "__init__", m__init__)


@pytest.fixture
def mock_notary_allow_leet(monkeypatch):
    def m_get_trusted_digest(host: str, image: Image, policy_rule: dict):
        if (
            image.digest
            == "1337133713371337133713371337133713371337133713371337133713371337"
        ):
            return "abcdefghijklmnopqrst"
        else:
            raise NotFoundException(
                'could not find signed digest for image "{}" in trust data.'.format(
                    str(image)
                )
            )

    monkeypatch.setattr(mutate, "get_trusted_digest", m_get_trusted_digest)


@pytest.fixture
def mock_mutate(monkeypatch):
    def m_get_parent_images(request: dict, index: int, namespace: str):
        return []

    monkeypatch.setattr(mutate, "get_parent_images", m_get_parent_images)


@pytest.fixture
def mock_notary(monkeypatch):
    def config_init(self, config: dict):
        self.name = config.get("name")
        self.host = config.get("host")
        self.root_keys = config.get("rootKeys")
        self.is_acr = config.get("isAcr")
        self.auth = config.get("auth")
        self.has_auth = config.get("hasAuth")
        self.is_selfsigned = config.get("isSelfsigned")
        self.selfsigned_cert = config.get("selfsignedCert")

    def config_get_key(self, key_name: str = None):
        if key_name:
            key = next(
                key_.get("key")
                for key_ in self.root_keys
                if key_.get("name") == key_name
            )
        else:
            key = self.root_keys[0].get("key")
        return key

    def config_get_auth(self):
        return self.auth

    def config_get_selfsigned_cert(self):
        return self.selfsigned_cert

    monkeypatch.setattr(Notary, "__init__", config_init)
    monkeypatch.setattr(Notary, "get_key", config_get_key)
    monkeypatch.setattr(Notary, "get_auth", config_get_auth)
    monkeypatch.setattr(Notary, "get_selfsigned_cert", config_get_selfsigned_cert)


@pytest.fixture
def mock_config(monkeypatch):
    def config_init(self):
        self.notaries = [Notary(notary) for notary in sample_config]

    monkeypatch.setattr(Config, "__init__", config_init)


def get_file_json(path: str):
    with open(path, "r") as file:
        return json.load(file)


def test_healthz():
    assert fs.healthz() == ("", 200)


@pytest.mark.parametrize(
    "sentinel_name, webhook, status",
    [
        ("sample_sentinel_run", "", 200),
        ("sample_sentinel_fin", "", 500),
        ("sample_sentinel_err", "", 500),
        ("", "", 500),
        ("sample_sentinel_fin", "sample_webhook", 200),
        ("sample_sentinel_fin", "", 500),
    ],
)
def test_readyz(
    mock_kube_request,
    monkeypatch,
    sentinel_name,
    webhook,
    status,
):
    monkeypatch.setenv("CONNAISSEUR_NAMESPACE", "conny")
    monkeypatch.setenv("CONNAISSEUR_SENTINEL", sentinel_name)
    monkeypatch.setenv("CONNAISSEUR_WEBHOOK", webhook)

    assert fs.readyz() == ("", status)


@pytest.mark.parametrize(
    "name",
    [("ad_request_deployments"), ("ad_request_pods"), ("ad_request_replicasets")],
)
def test_mutate_no_verify(
    mock_mutate, mock_policy_no_verify, mock_config, mock_notary, name
):
    client = fs.APP.test_client()

    mock_request_data = get_file_json(f"tests/data/{name}.json")
    response = client.post("/mutate", json=mock_request_data)
    assert response.status_code == 200
    assert response.is_json
    admission_response = response.get_json()["response"]
    assert admission_response["allowed"] == True
    assert admission_response["status"]["code"] == 202
    assert not "response" in admission_response["status"]


@pytest.mark.parametrize(
    "name, api_version, allowed, code, message",
    [
        ("ad_request_pods", "v2", False, 403, "API version v2 unknown."),
        (
            "sample_releases",
            "admission.k8s.io/v1beta1",
            False,
            403,
            "unknown request object kind None",
        ),
    ],
)
def test_mutate_invalid(monkeypatch, name, api_version, allowed, code, message):
    monkeypatch.setenv("DETECTION_MODE", "0")
    client = fs.APP.test_client()

    mock_request_data = get_file_json(f"tests/data/{name}.json")
    mock_request_data["apiVersion"] = api_version
    response = client.post("/mutate", json=mock_request_data)
    assert response.status_code == 200
    assert response.is_json
    admission_response = response.get_json()["response"]
    assert admission_response["allowed"] == allowed
    assert admission_response["status"]["code"] == code
    assert admission_response["status"]["message"] == message


@pytest.mark.parametrize(
    "name, allowed, image, detection",
    [
        (
            "ad_request_pods",
            False,
            "someguy/charlie-image@sha256:91ac9b26df583762234c1cdb2fc930364754ccc59bc752a2bfe298d2ea68f9ff",
            "0",
        ),
        (
            "ad_request_pods",
            False,
            "docker.io/someguy/charlie-image@sha256:91ac9b26df583762234c1cdb2fc930364754ccc59bc752a2bfe298d2ea68f9ff",
            "0",
        ),
        (
            "ad_request_pods",
            False,
            "docker.io/alice/goes-to-town-image@sha256:deadbeafdeadbeafdeadbeafdeadbeafdeadbeafdeadbeafdeadbeafdeadbeaf",
            "1",
        ),
        (
            "ad_request_pods",
            True,
            "someguy/bob-image@sha256:1337133713371337133713371337133713371337133713371337133713371337",
            "0",
        ),
        (
            "ad_request_pods",
            True,
            "docker.io/theotherguy/benign@sha256:1337133713371337133713371337133713371337133713371337133713371337",
            "1",
        ),
    ],
)
def test_mutate_verify(
    mock_mutate,
    mock_policy_verify,
    mock_notary_allow_leet,
    mock_config,
    mock_notary,
    name,
    allowed,
    image,
    detection,
    monkeypatch,
):
    monkeypatch.setenv("DETECTION_MODE", detection)
    client = fs.APP.test_client()

    mock_request_data = get_file_json(f"tests/data/{name}.json")
    mock_request_data["request"]["object"]["spec"]["containers"][0]["image"] = image
    response = client.post("/mutate", json=mock_request_data)
    assert response.status_code == 200
    assert response.is_json

    admission_response = response.get_json()["response"]

    assert admission_response["allowed"] == allowed

    if allowed:
        assert admission_response["status"]["code"] == 202
        assert not "message" in admission_response["status"]
    else:
        assert admission_response["status"]["code"] == 403
        image = (
            image
            if image.startswith("docker.io/")
            else "{}{}".format("docker.io/", image)
        )
        detection_mode_string = (
            " (not denied due to DETECTION_MODE)" if detection == "1" else ""
        )
        expected_message = (
            'could not find signed digest for image "{}" in trust data.{}'.format(
                image, detection_mode_string
            )
        )
        assert admission_response["status"]["message"] == expected_message
