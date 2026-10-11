from app.core.config import Settings, get_settings


def test_default_settings():
    settings = Settings()
    assert settings.app_name == "24/7 Intelligent Code Reviewer"
    assert settings.port == 8080
    assert settings.secret_scanning_enabled is True
    assert settings.pii_redaction_enabled is True
    assert settings.prompt_injection_defense_enabled is True
    assert settings.entropy_threshold == 4.5


def test_get_settings_caching():
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2
