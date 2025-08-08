import pytest
from unittest.mock import patch, MagicMock
from dremioai.config.settings import Settings, Dremio
from dremioai.api.transport import DremioAsyncHttpClient, AsyncHttpClient, _get_token_from_username_password

@patch('requests.post')
def test_get_token_from_username_password(mock_post):
    # Arrange
    mock_response = MagicMock()
    mock_response.json.return_value = {"token": "test_token"}
    mock_post.return_value = mock_response

    # Act
    token = _get_token_from_username_password("http://test.com", "user", "pass")

    # Assert
    mock_post.assert_called_once_with(
        "http://test.com/apiv2/login",
        json={"userName": "user", "password": "pass"},
        verify=False
    )
    assert token == "test_token"

def test_dremio_async_http_client_with_pat():
    # Arrange
    settings = Settings(
        dremio=Dremio(
            uri="https://datacolabs.samsungds.net",
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
            uri="https://datacolabs.samsungds.net"
        )
    )

    # Act & Assert
    with pytest.raises(ValueError, match="Either a PAT or a username/password must be supplied for Dremio authentication."):
        with patch('dremioai.config.settings.instance', return_value=settings):
            DremioAsyncHttpClient()
