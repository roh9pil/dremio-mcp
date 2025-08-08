import pytest
from unittest.mock import patch, MagicMock
from dremioai.config.settings import Settings, Dremio
from dremioai.api.transport import DremioAsyncHttpClient

@patch('requests.post')
def test_dremio_async_http_client_with_username_password(mock_post):
    # Arrange
    mock_response = MagicMock()
    mock_response.json.return_value = {"token": "test_token"}
    mock_post.return_value = mock_response

    settings = Settings(
        dremio=Dremio(
            uri="http://localhost:9047",
            username="test_user",
            password="test_password"
        )
    )

    # Act
    with patch('dremioai.config.settings.instance', return_value=settings):
        client = DremioAsyncHttpClient()

    # Assert
    mock_post.assert_called_once_with(
        "http://localhost:9047/oauth/token",
        data={
            "grant_type": "password",
            "username": "test_user",
            "password": "test_password",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert client.headers["Authorization"] == "Bearer test_token"

def test_dremio_async_http_client_with_pat():
    # Arrange
    settings = Settings(
        dremio=Dremio(
            uri="http://localhost:9047",
            pat="test_pat"
        )
    )

    # Act
    with patch('dremioai.config.settings.instance', return_value=settings):
        client = DremioAsyncHttpClient()

    # Assert
    assert client.headers["Authorization"] == "Bearer test_pat"

def test_dremio_async_http_client_no_auth():
    # Arrange
    settings = Settings(
        dremio=Dremio(
            uri="http://localhost:9047"
        )
    )

    # Act & Assert
    with pytest.raises(ValueError, match="Either a PAT or a username/password must be supplied for Dremio authentication."):
        with patch('dremioai.config.settings.instance', return_value=settings):
            DremioAsyncHttpClient()
