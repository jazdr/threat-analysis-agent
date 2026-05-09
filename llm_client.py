"""LLM 클라이언트 (OpenAI-compatible API)"""

from openai import OpenAI
import config


class LLMClient:
    """OpenAI-compatible API를 통한 로컬 LLM 호출"""

    def __init__(
        self,
        base_url: str = config.LLM_BASE_URL,
        api_key: str = config.LLM_API_KEY,
        model: str = config.LLM_MODEL,
        temperature: float = config.LLM_TEMPERATURE,
        max_tokens: int = config.LLM_MAX_TOKENS,
        timeout: int = config.LLM_TIMEOUT,
    ):
        self.client = OpenAI(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
        )
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def chat_completion(self, system_prompt: str | None, user_prompt: str) -> str:
        """
        메시지를 전송하고 텍스트 응답을 반환합니다.
        system_prompt가 None이면 user 메시지만 전송합니다.
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        content = response.choices[0].message.content
        return content.strip() if content else ""

    def test_connection(self) -> bool:
        """간단한 ping 테스트"""
        try:
            self.chat_completion(None, "Say 'pong' only.")
            return True
        except Exception:
            return False


if __name__ == "__main__":
    client = LLMClient()
    print("Connection test:", client.test_connection())
    print("Sample response:", client.chat_completion(None, "SELECT 1; 를 한국어로 설명해줘."))
