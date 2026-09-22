from backend.app.scanner import scan_text


def test_detects_email_and_ip():
    result = scan_text("Contact alice@example.com from 192.168.1.20")
    assert result["summary"]["total"] == 2
    assert {item["type"] for item in result["findings"]} == {"email", "ipv4"}


def test_detects_jwt_as_critical():
    result = scan_text("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature")
    assert result["risk"] == "critical"
    assert result["findings"][0]["type"] == "jwt"


def test_invalid_card_is_not_reported():
    result = scan_text("number 4111 1111 1111 1112")
    assert result["summary"]["total"] == 0
