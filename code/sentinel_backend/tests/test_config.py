from app.core.config import Settings


def test_cors_origins_accept_comma_separated_environment_value() -> None:
    settings = Settings(
        _env_file=None,
        CORS_ORIGINS="https://console.example,https://admin.example",
    )

    assert settings.CORS_ORIGINS == [
        "https://console.example",
        "https://admin.example",
    ]


def test_production_sensitive_defaults_are_safe() -> None:
    settings = Settings(_env_file=None)

    assert settings.ML_AGENT_A_URL
    assert settings.SQL_ECHO is False
    assert settings.SANDBOX_ALLOW_PRIVILEGED is False
    assert settings.SANDBOX_NETWORK_DISABLED is True
