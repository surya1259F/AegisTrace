import pytest
import httpx
import re

from backend.app.services.ai_provider import (
    ProviderId,
    ProviderRequest,
    ProviderResponse,
    ProviderError,
    OpenAIAdapter,
    AnthropicAdapter,
    GeminiAdapter,
    LocalOpenAIAdapter,
    get_ai_adapter,
    DEFAULT_TIMEOUT
)

MOCK_SECRET_KEY = "sk-proj-test1234567890secretkey12345"

# -----------------------------------------------------------------------------
# 1-4: OpenAI Adapter Tests
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_1_openai_success():
    def handler(request: httpx.Request):
        assert request.headers["authorization"] == f"Bearer {MOCK_SECRET_KEY}"
        return httpx.Response(200, json={
            "id": "chatcmpl-123",
            "choices": [{"message": {"role": "assistant", "content": "OpenAI generated analysis"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        })

    adapter = OpenAIAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.OPENAI,
        model="gpt-4o-mini",
        prompt="Analyze memory dump",
        api_key=MOCK_SECRET_KEY
    )
    res = await adapter.generate(req)
    assert res.provider == ProviderId.OPENAI
    assert res.content == "OpenAI generated analysis"
    assert res.request_id == "chatcmpl-123"
    assert res.usage == {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}

@pytest.mark.asyncio
async def test_2_openai_http_error():
    def handler(request: httpx.Request):
        return httpx.Response(401, json={"error": {"message": "Invalid API key provided"}})

    adapter = OpenAIAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.OPENAI,
        model="gpt-4o-mini",
        prompt="Analyze",
        api_key=MOCK_SECRET_KEY
    )
    with pytest.raises(ProviderError) as exc_info:
        await adapter.generate(req)
    assert exc_info.value.status_code == 401
    assert MOCK_SECRET_KEY not in str(exc_info.value)

@pytest.mark.asyncio
async def test_3_openai_timeout():
    def handler(request: httpx.Request):
        raise httpx.TimeoutException("Connection timed out")

    adapter = OpenAIAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.OPENAI,
        model="gpt-4o-mini",
        prompt="Analyze",
        api_key=MOCK_SECRET_KEY
    )
    with pytest.raises(ProviderError) as exc_info:
        await adapter.generate(req)
    assert "timed out" in str(exc_info.value).lower()
    assert MOCK_SECRET_KEY not in str(exc_info.value)

@pytest.mark.asyncio
async def test_4_openai_malformed_response():
    def handler(request: httpx.Request):
        return httpx.Response(200, text="NOT_VALID_JSON")

    adapter = OpenAIAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.OPENAI,
        model="gpt-4o-mini",
        prompt="Analyze",
        api_key=MOCK_SECRET_KEY
    )
    with pytest.raises(ProviderError) as exc_info:
        await adapter.generate(req)
    assert "malformed" in str(exc_info.value).lower()

# -----------------------------------------------------------------------------
# 5-8: Anthropic Adapter Tests
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_5_anthropic_success():
    def handler(request: httpx.Request):
        assert request.headers["x-api-key"] == MOCK_SECRET_KEY
        return httpx.Response(200, json={
            "id": "msg_013Z95v5",
            "content": [{"type": "text", "text": "Claude generated analysis"}],
            "usage": {"input_tokens": 12, "output_tokens": 8}
        })

    adapter = AnthropicAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.ANTHROPIC,
        model="claude-3-5-sonnet-20241022",
        prompt="Analyze malware sample",
        api_key=MOCK_SECRET_KEY
    )
    res = await adapter.generate(req)
    assert res.provider == ProviderId.ANTHROPIC
    assert res.content == "Claude generated analysis"
    assert res.request_id == "msg_013Z95v5"

@pytest.mark.asyncio
async def test_6_anthropic_http_error():
    def handler(request: httpx.Request):
        return httpx.Response(403, json={"error": {"type": "authentication_error", "message": "invalid x-api-key"}})

    adapter = AnthropicAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.ANTHROPIC,
        model="claude-3-5-sonnet-20241022",
        prompt="Analyze",
        api_key=MOCK_SECRET_KEY
    )
    with pytest.raises(ProviderError) as exc_info:
        await adapter.generate(req)
    assert exc_info.value.status_code == 403
    assert MOCK_SECRET_KEY not in str(exc_info.value)

@pytest.mark.asyncio
async def test_7_anthropic_timeout():
    def handler(request: httpx.Request):
        raise httpx.TimeoutException("Read timeout")

    adapter = AnthropicAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.ANTHROPIC,
        model="claude-3-5-sonnet-20241022",
        prompt="Analyze",
        api_key=MOCK_SECRET_KEY
    )
    with pytest.raises(ProviderError) as exc_info:
        await adapter.generate(req)
    assert "timed out" in str(exc_info.value).lower()

@pytest.mark.asyncio
async def test_8_anthropic_malformed_response():
    def handler(request: httpx.Request):
        return httpx.Response(200, json={"content": []}) # missing text block

    adapter = AnthropicAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.ANTHROPIC,
        model="claude-3-5-sonnet-20241022",
        prompt="Analyze",
        api_key=MOCK_SECRET_KEY
    )
    with pytest.raises(ProviderError) as exc_info:
        await adapter.generate(req)
    assert "malformed" in str(exc_info.value).lower()

# -----------------------------------------------------------------------------
# 9-12: Gemini Adapter Tests
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_9_gemini_success():
    def handler(request: httpx.Request):
        assert request.headers["x-goog-api-key"] == MOCK_SECRET_KEY
        return httpx.Response(200, json={
            "candidates": [{
                "content": {"parts": [{"text": "Gemini generated analysis"}]}
            }],
            "usageMetadata": {"promptTokenCount": 8, "candidatesTokenCount": 4}
        })

    adapter = GeminiAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.GEMINI,
        model="gemini-1.5-flash",
        prompt="Analyze EVTX logs",
        api_key=MOCK_SECRET_KEY
    )
    res = await adapter.generate(req)
    assert res.provider == ProviderId.GEMINI
    assert res.content == "Gemini generated analysis"

@pytest.mark.asyncio
async def test_10_gemini_http_error():
    def handler(request: httpx.Request):
        return httpx.Response(400, json={"error": {"code": 400, "message": "API key not valid."}})

    adapter = GeminiAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.GEMINI,
        model="gemini-1.5-flash",
        prompt="Analyze",
        api_key=MOCK_SECRET_KEY
    )
    with pytest.raises(ProviderError) as exc_info:
        await adapter.generate(req)
    assert exc_info.value.status_code == 400
    assert MOCK_SECRET_KEY not in str(exc_info.value)

@pytest.mark.asyncio
async def test_11_gemini_timeout():
    def handler(request: httpx.Request):
        raise httpx.TimeoutException("Gemini server timeout")

    adapter = GeminiAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.GEMINI,
        model="gemini-1.5-flash",
        prompt="Analyze",
        api_key=MOCK_SECRET_KEY
    )
    with pytest.raises(ProviderError) as exc_info:
        await adapter.generate(req)
    assert "timed out" in str(exc_info.value).lower()

@pytest.mark.asyncio
async def test_12_gemini_malformed_response():
    def handler(request: httpx.Request):
        return httpx.Response(200, json={"candidates": []}) # missing candidates

    adapter = GeminiAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.GEMINI,
        model="gemini-1.5-flash",
        prompt="Analyze",
        api_key=MOCK_SECRET_KEY
    )
    with pytest.raises(ProviderError) as exc_info:
        await adapter.generate(req)
    assert "malformed" in str(exc_info.value).lower()

# -----------------------------------------------------------------------------
# 13-15: Local OpenAI-Compatible Tests
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_13_local_openai_success():
    def handler(request: httpx.Request):
        return httpx.Response(200, json={
            "id": "ollama-123",
            "choices": [{"message": {"role": "assistant", "content": "Ollama local analysis"}}]
        })

    adapter = LocalOpenAIAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.LOCAL_OPENAI,
        model="llama3",
        prompt="Local analysis prompt",
        base_url="http://localhost:11434/v1"
    )
    res = await adapter.generate(req)
    assert res.provider == ProviderId.LOCAL_OPENAI
    assert res.content == "Ollama local analysis"

@pytest.mark.asyncio
async def test_14_local_http_error():
    def handler(request: httpx.Request):
        return httpx.Response(500, text="Internal Server Error")

    adapter = LocalOpenAIAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.LOCAL_OPENAI,
        model="llama3",
        prompt="Analyze",
        base_url="http://localhost:11434/v1"
    )
    with pytest.raises(ProviderError) as exc_info:
        await adapter.generate(req)
    assert exc_info.value.status_code == 500

@pytest.mark.asyncio
async def test_15_local_malformed_response():
    def handler(request: httpx.Request):
        return httpx.Response(200, text="INVALID_JSON")

    adapter = LocalOpenAIAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.LOCAL_OPENAI,
        model="llama3",
        prompt="Analyze",
        base_url="http://localhost:11434/v1"
    )
    with pytest.raises(ProviderError) as exc_info:
        await adapter.generate(req)
    assert "malformed" in str(exc_info.value).lower()

# -----------------------------------------------------------------------------
# 16-22: General Security & Architecture Tests
# -----------------------------------------------------------------------------

def test_16_invalid_provider_configuration():
    with pytest.raises(ProviderError) as exc_info:
        get_ai_adapter("invalid_provider_name")
    assert "not a supported" in str(exc_info.value).lower()

@pytest.mark.asyncio
async def test_17_api_key_never_appears_in_normalized_response():
    def handler(request: httpx.Request):
        return httpx.Response(200, json={
            "id": "chatcmpl-1",
            "choices": [{"message": {"role": "assistant", "content": "Analysis content"}}]
        })

    adapter = OpenAIAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.OPENAI,
        model="gpt-4o-mini",
        prompt="Analyze",
        api_key=MOCK_SECRET_KEY
    )
    res = await adapter.generate(req)
    res_json = res.model_dump_json()
    assert MOCK_SECRET_KEY not in res_json

@pytest.mark.asyncio
async def test_18_api_key_never_appears_in_normalized_exception():
    err = ProviderError(ProviderId.OPENAI, f"Failed request with Authorization: Bearer {MOCK_SECRET_KEY}")
    assert MOCK_SECRET_KEY not in str(err)
    assert MOCK_SECRET_KEY not in err.message
    assert "[REDACTED]" in str(err)

@pytest.mark.asyncio
async def test_19_api_key_never_appears_in_logging_or_str(capsys):
    err = ProviderError(ProviderId.OPENAI, f"Header x-api-key: {MOCK_SECRET_KEY} failed")
    print(f"Logged Exception: {err}")
    captured = capsys.readouterr()
    assert MOCK_SECRET_KEY not in captured.out
    assert "[REDACTED]" in captured.out

@pytest.mark.asyncio
async def test_20_https_enforcement_for_external_providers():
    adapter = OpenAIAdapter()
    req = ProviderRequest(
        provider=ProviderId.OPENAI,
        model="gpt-4o-mini",
        prompt="Analyze",
        api_key=MOCK_SECRET_KEY,
        base_url="http://insecure-cloud-endpoint.com/v1" # Insecure HTTP
    )
    with pytest.raises(ProviderError) as exc_info:
        await adapter.generate(req)
    assert "requires https" in str(exc_info.value).lower()

@pytest.mark.asyncio
async def test_21_explicitly_permitted_local_http_behavior():
    def handler(request: httpx.Request):
        return httpx.Response(200, json={"choices": [{"message": {"content": "OK"}}]})

    adapter = LocalOpenAIAdapter(transport=httpx.MockTransport(handler))
    req = ProviderRequest(
        provider=ProviderId.LOCAL_OPENAI,
        model="llama3",
        prompt="Analyze",
        base_url="http://localhost:11434/v1" # Local HTTP is explicitly permitted
    )
    res = await adapter.generate(req)
    assert res.content == "OK"

def test_22_timeout_values_are_bounded():
    assert DEFAULT_TIMEOUT.connect == 5.0
    assert DEFAULT_TIMEOUT.read == 15.0
    assert DEFAULT_TIMEOUT.write == 5.0

