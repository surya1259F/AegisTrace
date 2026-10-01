from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, List, Optional
import json
import logging
import re
import time
from pydantic import BaseModel, Field, ConfigDict
import httpx

logger = logging.getLogger("ADFIR_AI_PROVIDER")

DEFAULT_TIMEOUT = httpx.Timeout(15.0, connect=5.0, read=15.0, write=5.0)


class ProviderId(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    LOCAL_OPENAI = "local_openai"
    LOCAL_STUB = "local_stub"


class ConnectionTestResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    provider: ProviderId
    success: bool
    status_message: str
    latency_ms: Optional[float] = None
    has_key: bool = False


class ProviderRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    provider: ProviderId
    model: str
    prompt: str
    system_prompt: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 1000
    api_key: Optional[str] = None
    base_url: Optional[str] = None


class ProviderResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    provider: ProviderId
    model: str
    content: str
    request_id: Optional[str] = None
    usage: Optional[Dict[str, int]] = None


class ProviderError(Exception):
    """
    Sanitized provider exception.
    Guarantees API keys and Authorization headers are NEVER exposed in error message or str representation.
    """
    def __init__(self, provider: ProviderId, message: str, status_code: Optional[int] = None):
        sanitized_msg = self._sanitize(message)
        super().__init__(sanitized_msg)
        self.provider = provider
        self.message = sanitized_msg
        self.status_code = status_code

    @staticmethod
    def _sanitize(text: str) -> str:
        if not text:
            return "Unknown provider error"
        sanitized = text
        sanitized = re.sub(r'Bearer\s+[A-Za-z0-9_\-\.]+', 'Bearer [REDACTED]', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'x-api-key["\']?\s*[:=]\s*["\']?[A-Za-z0-9_\-\.]+', 'x-api-key: [REDACTED]', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'x-goog-api-key["\']?\s*[:=]\s*["\']?[A-Za-z0-9_\-\.]+', 'x-goog-api-key: [REDACTED]', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'sk-[A-Za-z0-9_-]{8,}', 'sk-[REDACTED]', sanitized)
        return sanitized


class BaseAIAdapter(ABC):
    def __init__(
        self,
        provider_id: ProviderId,
        default_model: str,
        transport: Optional[httpx.AsyncBaseTransport] = None
    ):
        self.provider_id = provider_id
        self.default_model = default_model
        self.transport = transport

    def _get_client(self, timeout: Optional[httpx.Timeout] = None) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=self.transport,
            timeout=timeout or DEFAULT_TIMEOUT
        )

    def _validate_https_url(self, url: str, is_local: bool = False):
        url_clean = url.lower().strip()
        if not is_local and url_clean.startswith("http://"):
            raise ProviderError(
                self.provider_id,
                f"Security Policy Error: External provider '{self.provider_id.value}' requires HTTPS. HTTP is prohibited for cloud endpoints."
            )

    @abstractmethod
    async def test_connection(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None
    ) -> ConnectionTestResult:
        pass

    @abstractmethod
    async def generate(self, req: ProviderRequest) -> ProviderResponse:
        pass


class OpenAIAdapter(BaseAIAdapter):
    DEFAULT_BASE_URL = "https://api.openai.com/v1"
    DEFAULT_MODEL = "gpt-4o-mini"

    def __init__(self, transport: Optional[httpx.AsyncBaseTransport] = None):
        super().__init__(ProviderId.OPENAI, self.DEFAULT_MODEL, transport)

    async def test_connection(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None
    ) -> ConnectionTestResult:
        if not api_key:
            return ConnectionTestResult(
                provider=self.provider_id,
                success=False,
                status_message="API key is required for OpenAI provider connection test.",
                has_key=False
            )
        target_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self._validate_https_url(target_url, is_local=False)

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        start_time = time.time()
        try:
            async with self._get_client() as client:
                res = await client.get(f"{target_url}/models", headers=headers)
                latency = round((time.time() - start_time) * 1000, 2)

                if res.status_code == 200:
                    return ConnectionTestResult(
                        provider=self.provider_id,
                        success=True,
                        status_message="OpenAI API connection verified successfully.",
                        latency_ms=latency,
                        has_key=True
                    )
                else:
                    return ConnectionTestResult(
                        provider=self.provider_id,
                        success=False,
                        status_message=f"OpenAI API returned HTTP {res.status_code}",
                        latency_ms=latency,
                        has_key=True
                    )
        except httpx.TimeoutException:
            return ConnectionTestResult(
                provider=self.provider_id,
                success=False,
                status_message="Connection timed out connecting to OpenAI API.",
                has_key=True
            )
        except Exception as e:
            return ConnectionTestResult(
                provider=self.provider_id,
                success=False,
                status_message=ProviderError._sanitize(str(e)),
                has_key=True
            )

    async def generate(self, req: ProviderRequest) -> ProviderResponse:
        if not req.api_key:
            raise ProviderError(self.provider_id, "API key is required for OpenAI provider generation.")

        target_url = (req.base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self._validate_https_url(target_url, is_local=False)

        headers = {
            "Authorization": f"Bearer {req.api_key}",
            "Content-Type": "application/json"
        }

        messages = []
        if req.system_prompt:
            messages.append({"role": "system", "content": req.system_prompt})
        messages.append({"role": "user", "content": req.prompt})

        payload = {
            "model": req.model or self.DEFAULT_MODEL,
            "messages": messages,
            "temperature": req.temperature,
            "max_tokens": req.max_tokens
        }

        try:
            async with self._get_client() as client:
                res = await client.post(f"{target_url}/chat/completions", headers=headers, json=payload)
                if res.status_code != 200:
                    raise ProviderError(
                        self.provider_id,
                        f"OpenAI API error HTTP {res.status_code}: {res.text}",
                        status_code=res.status_code
                    )

                data = res.json()
                if "choices" not in data or not data["choices"]:
                    raise ProviderError(self.provider_id, "OpenAI API returned malformed response: missing choices.")

                choice = data["choices"][0]
                content = choice.get("message", {}).get("content", "")
                if content is None:
                    content = ""

                usage = data.get("usage", {})
                req_id = data.get("id")

                return ProviderResponse(
                    provider=self.provider_id,
                    model=req.model or self.DEFAULT_MODEL,
                    content=content,
                    request_id=req_id,
                    usage=usage if isinstance(usage, dict) else None
                )

        except httpx.TimeoutException:
            raise ProviderError(self.provider_id, "OpenAI API request timed out.")
        except json.JSONDecodeError:
            raise ProviderError(self.provider_id, "OpenAI API returned malformed non-JSON response.")
        except ProviderError:
            raise
        except Exception as e:
            raise ProviderError(self.provider_id, f"OpenAI API execution error: {str(e)}")


class AnthropicAdapter(BaseAIAdapter):
    DEFAULT_BASE_URL = "https://api.anthropic.com/v1"
    DEFAULT_MODEL = "claude-3-5-sonnet-20241022"

    def __init__(self, transport: Optional[httpx.AsyncBaseTransport] = None):
        super().__init__(ProviderId.ANTHROPIC, self.DEFAULT_MODEL, transport)

    async def test_connection(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None
    ) -> ConnectionTestResult:
        if not api_key:
            return ConnectionTestResult(
                provider=self.provider_id,
                success=False,
                status_message="API key is required for Anthropic provider connection test.",
                has_key=False
            )
        target_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self._validate_https_url(target_url, is_local=False)

        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        start_time = time.time()
        try:
            async with self._get_client() as client:
                res = await client.post(
                    f"{target_url}/messages",
                    headers=headers,
                    json={
                        "model": self.DEFAULT_MODEL,
                        "max_tokens": 10,
                        "messages": [{"role": "user", "content": "ping"}]
                    }
                )
                latency = round((time.time() - start_time) * 1000, 2)

                if res.status_code in (200, 400): # 200 OK or 400 with valid key structure
                    return ConnectionTestResult(
                        provider=self.provider_id,
                        success=res.status_code == 200,
                        status_message="Anthropic API connection verified successfully." if res.status_code == 200 else f"Anthropic API returned HTTP {res.status_code}",
                        latency_ms=latency,
                        has_key=True
                    )
                else:
                    return ConnectionTestResult(
                        provider=self.provider_id,
                        success=False,
                        status_message=f"Anthropic API returned HTTP {res.status_code}",
                        latency_ms=latency,
                        has_key=True
                    )
        except httpx.TimeoutException:
            return ConnectionTestResult(
                provider=self.provider_id,
                success=False,
                status_message="Connection timed out connecting to Anthropic API.",
                has_key=True
            )
        except Exception as e:
            return ConnectionTestResult(
                provider=self.provider_id,
                success=False,
                status_message=ProviderError._sanitize(str(e)),
                has_key=True
            )

    async def generate(self, req: ProviderRequest) -> ProviderResponse:
        if not req.api_key:
            raise ProviderError(self.provider_id, "API key is required for Anthropic provider generation.")

        target_url = (req.base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self._validate_https_url(target_url, is_local=False)

        headers = {
            "x-api-key": req.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }

        payload: Dict[str, Any] = {
            "model": req.model or self.DEFAULT_MODEL,
            "max_tokens": req.max_tokens,
            "messages": [{"role": "user", "content": req.prompt}]
        }
        if req.system_prompt:
            payload["system"] = req.system_prompt

        try:
            async with self._get_client() as client:
                res = await client.post(f"{target_url}/messages", headers=headers, json=payload)
                if res.status_code != 200:
                    raise ProviderError(
                        self.provider_id,
                        f"Anthropic API error HTTP {res.status_code}: {res.text}",
                        status_code=res.status_code
                    )

                data = res.json()
                if "content" not in data or not isinstance(data["content"], list) or not data["content"]:
                    raise ProviderError(self.provider_id, "Anthropic API returned malformed response: missing content block.")

                text_content = ""
                for block in data["content"]:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text_content += block.get("text", "")

                req_id = data.get("id")
                usage = data.get("usage", {})

                return ProviderResponse(
                    provider=self.provider_id,
                    model=req.model or self.DEFAULT_MODEL,
                    content=text_content,
                    request_id=req_id,
                    usage=usage if isinstance(usage, dict) else None
                )

        except httpx.TimeoutException:
            raise ProviderError(self.provider_id, "Anthropic API request timed out.")
        except json.JSONDecodeError:
            raise ProviderError(self.provider_id, "Anthropic API returned malformed non-JSON response.")
        except ProviderError:
            raise
        except Exception as e:
            raise ProviderError(self.provider_id, f"Anthropic API execution error: {str(e)}")


class GeminiAdapter(BaseAIAdapter):
    DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
    DEFAULT_MODEL = "gemini-1.5-flash"

    def __init__(self, transport: Optional[httpx.AsyncBaseTransport] = None):
        super().__init__(ProviderId.GEMINI, self.DEFAULT_MODEL, transport)

    async def test_connection(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None
    ) -> ConnectionTestResult:
        if not api_key:
            return ConnectionTestResult(
                provider=self.provider_id,
                success=False,
                status_message="API key is required for Google Gemini provider connection test.",
                has_key=False
            )
        target_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self._validate_https_url(target_url, is_local=False)

        headers = {
            "x-goog-api-key": api_key,
            "Content-Type": "application/json"
        }
        start_time = time.time()
        try:
            async with self._get_client() as client:
                res = await client.post(
                    f"{target_url}/models/{self.DEFAULT_MODEL}:generateContent",
                    headers=headers,
                    json={"contents": [{"parts": [{"text": "ping"}]}]}
                )
                latency = round((time.time() - start_time) * 1000, 2)

                if res.status_code == 200:
                    return ConnectionTestResult(
                        provider=self.provider_id,
                        success=True,
                        status_message="Google Gemini API connection verified successfully.",
                        latency_ms=latency,
                        has_key=True
                    )
                else:
                    return ConnectionTestResult(
                        provider=self.provider_id,
                        success=False,
                        status_message=f"Google Gemini API returned HTTP {res.status_code}",
                        latency_ms=latency,
                        has_key=True
                    )
        except httpx.TimeoutException:
            return ConnectionTestResult(
                provider=self.provider_id,
                success=False,
                status_message="Connection timed out connecting to Google Gemini API.",
                has_key=True
            )
        except Exception as e:
            return ConnectionTestResult(
                provider=self.provider_id,
                success=False,
                status_message=ProviderError._sanitize(str(e)),
                has_key=True
            )

    async def generate(self, req: ProviderRequest) -> ProviderResponse:
        if not req.api_key:
            raise ProviderError(self.provider_id, "API key is required for Google Gemini provider generation.")

        target_url = (req.base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self._validate_https_url(target_url, is_local=False)

        headers = {
            "x-goog-api-key": req.api_key,
            "Content-Type": "application/json"
        }

        model_name = req.model or self.DEFAULT_MODEL
        payload: Dict[str, Any] = {
            "contents": [{"parts": [{"text": req.prompt}]}]
        }
        if req.system_prompt:
            payload["systemInstruction"] = {"parts": [{"text": req.system_prompt}]}

        try:
            async with self._get_client() as client:
                res = await client.post(
                    f"{target_url}/models/{model_name}:generateContent",
                    headers=headers,
                    json=payload
                )
                if res.status_code != 200:
                    raise ProviderError(
                        self.provider_id,
                        f"Google Gemini API error HTTP {res.status_code}: {res.text}",
                        status_code=res.status_code
                    )

                data = res.json()
                if "candidates" not in data or not data["candidates"]:
                    raise ProviderError(self.provider_id, "Google Gemini API returned malformed response: missing candidates.")

                candidate = data["candidates"][0]
                parts = candidate.get("content", {}).get("parts", [])
                text_content = "".join([p.get("text", "") for p in parts if isinstance(p, dict)])

                usage = data.get("usageMetadata", {})

                return ProviderResponse(
                    provider=self.provider_id,
                    model=model_name,
                    content=text_content,
                    usage=usage if isinstance(usage, dict) else None
                )

        except httpx.TimeoutException:
            raise ProviderError(self.provider_id, "Google Gemini API request timed out.")
        except json.JSONDecodeError:
            raise ProviderError(self.provider_id, "Google Gemini API returned malformed non-JSON response.")
        except ProviderError:
            raise
        except Exception as e:
            raise ProviderError(self.provider_id, f"Google Gemini API execution error: {str(e)}")


class LocalOpenAIAdapter(BaseAIAdapter):
    DEFAULT_BASE_URL = "http://localhost:11434/v1"
    DEFAULT_MODEL = "llama3"

    def __init__(self, transport: Optional[httpx.AsyncBaseTransport] = None):
        super().__init__(ProviderId.LOCAL_OPENAI, self.DEFAULT_MODEL, transport)

    async def test_connection(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None
    ) -> ConnectionTestResult:
        target_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self._validate_https_url(target_url, is_local=True)

        start_time = time.time()
        try:
            async with self._get_client() as client:
                res = await client.get(f"{target_url}/models")
                latency = round((time.time() - start_time) * 1000, 2)

                if res.status_code == 200:
                    return ConnectionTestResult(
                        provider=self.provider_id,
                        success=True,
                        status_message="Local OpenAI-compatible API connection verified successfully.",
                        latency_ms=latency,
                        has_key=False
                    )
                else:
                    return ConnectionTestResult(
                        provider=self.provider_id,
                        success=False,
                        status_message=f"Local OpenAI API returned HTTP {res.status_code}",
                        latency_ms=latency,
                        has_key=False
                    )
        except httpx.TimeoutException:
            return ConnectionTestResult(
                provider=self.provider_id,
                success=False,
                status_message="Connection timed out connecting to local endpoint.",
                has_key=False
            )
        except Exception as e:
            return ConnectionTestResult(
                provider=self.provider_id,
                success=False,
                status_message=ProviderError._sanitize(str(e)),
                has_key=False
            )

    async def generate(self, req: ProviderRequest) -> ProviderResponse:
        target_url = (req.base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self._validate_https_url(target_url, is_local=True)

        headers = {"Content-Type": "application/json"}
        if req.api_key:
            headers["Authorization"] = f"Bearer {req.api_key}"

        messages = []
        if req.system_prompt:
            messages.append({"role": "system", "content": req.system_prompt})
        messages.append({"role": "user", "content": req.prompt})

        payload = {
            "model": req.model or self.DEFAULT_MODEL,
            "messages": messages,
            "temperature": req.temperature,
            "max_tokens": req.max_tokens
        }

        try:
            async with self._get_client() as client:
                res = await client.post(f"{target_url}/chat/completions", headers=headers, json=payload)
                if res.status_code != 200:
                    raise ProviderError(
                        self.provider_id,
                        f"Local OpenAI API error HTTP {res.status_code}: {res.text}",
                        status_code=res.status_code
                    )

                data = res.json()
                if "choices" not in data or not data["choices"]:
                    raise ProviderError(self.provider_id, "Local OpenAI API returned malformed response: missing choices.")

                choice = data["choices"][0]
                content = choice.get("message", {}).get("content", "")
                if content is None:
                    content = ""

                return ProviderResponse(
                    provider=self.provider_id,
                    model=req.model or self.DEFAULT_MODEL,
                    content=content,
                    request_id=data.get("id"),
                    usage=data.get("usage") if isinstance(data.get("usage"), dict) else None
                )

        except httpx.TimeoutException:
            raise ProviderError(self.provider_id, "Local OpenAI API request timed out.")
        except json.JSONDecodeError:
            raise ProviderError(self.provider_id, "Local OpenAI API returned malformed non-JSON response.")
        except ProviderError:
            raise
        except Exception as e:
            raise ProviderError(self.provider_id, f"Local OpenAI API execution error: {str(e)}")


def get_ai_adapter(
    provider_id: str | ProviderId,
    transport: Optional[httpx.AsyncBaseTransport] = None
) -> BaseAIAdapter:
    try:
        p_enum = ProviderId(str(provider_id).lower().strip()) if isinstance(provider_id, str) else provider_id
    except ValueError:
        raise ProviderError(
            ProviderId.LOCAL_STUB,
            f"Invalid provider configuration: '{provider_id}' is not a supported AI provider."
        )

    if p_enum == ProviderId.OPENAI:
        return OpenAIAdapter(transport=transport)
    elif p_enum == ProviderId.ANTHROPIC:
        return AnthropicAdapter(transport=transport)
    elif p_enum == ProviderId.GEMINI:
        return GeminiAdapter(transport=transport)
    elif p_enum == ProviderId.LOCAL_OPENAI:
        return LocalOpenAIAdapter(transport=transport)
    else:
        raise ProviderError(
            ProviderId.LOCAL_STUB,
            f"Invalid provider configuration: '{provider_id}' is not a supported AI provider."
        )
