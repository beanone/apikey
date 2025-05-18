from apikey.utils import generate_api_key, hash_api_key


def test_hash_api_key():
    key = "testkey123"
    result = hash_api_key(key)
    assert result
    assert isinstance(result, str)
    assert result == hash_api_key(key)  # Same input should produce same output


def test_generate_api_key():
    result = generate_api_key()
    assert result
    assert isinstance(result, str)
    assert (
        result != generate_api_key()
    )  # Different calls should produce different outputs
