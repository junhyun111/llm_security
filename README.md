# ai_vuln_analyzer

C/C++ 소스코드를 업로드하거나 경로로 지정하면 취약점을 분석하고, 패치 제안과 검증 결과를 리포트로 출력하는 Python 기반 MVP입니다.

## 설정 방식

이제 키와 모델은 프로젝트 루트의 `project_config.json`에서 관리합니다.

우선순위:

1. `project_config.json`
2. 환경변수
3. 코드 기본값

즉, 평소에는 환경변수 없이 `project_config.json`만 수정하면 됩니다.

## 주요 설정 파일

- 실제 사용 파일: [project_config.json](C:/Users/junhyun111/Desktop/llm_security/project_config.json:1)
- 예시 파일: [project_config.example.json](C:/Users/junhyun111/Desktop/llm_security/project_config.example.json:1)

OpenRouter를 쓸 경우 `project_config.json`을 이렇게 수정하면 됩니다.

```json
{
  "provider": "openrouter",
  "openrouter_api_key": "sk-or-v1-...",
  "openrouter_model": "anthropic/claude-3.5-sonnet",
  "openrouter_base_url": "https://openrouter.ai/api/v1",
  "openrouter_site_url": "http://localhost:8000",
  "openrouter_app_name": "ai-vuln-analyzer",
  "max_rounds": 3,
  "confidence_threshold": 0.8,
  "web_host": "127.0.0.1",
  "web_port": 8000
}
```

모델명은 여기서 관리합니다.

- `openrouter_model`
- `openai_model`
- `anthropic_model`

## 설치

### CLI만 먼저 실행

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install pydantic
```

### 웹 UI까지 포함한 권장 설치

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install --upgrade pip setuptools wheel
pip install -e .[dev,web]
```

OpenRouter 또는 OpenAI / Anthropic를 실제로 붙일 예정이면:

```powershell
pip install -e .[dev,web,openai,anthropic]
```

## CLI 실행

```powershell
$env:PYTHONPATH="src"
python -m ai_vuln_analyzer.cli scan <target_path> --provider mock
```

설정 파일의 provider를 그대로 쓰려면 `--provider`를 생략해도 됩니다.

```powershell
$env:PYTHONPATH="src"
python -m ai_vuln_analyzer.cli scan <target_path>
```

## 웹 실행

```powershell
$env:PYTHONPATH="src"
python -m ai_vuln_analyzer.cli serve
```

브라우저에서 `http://127.0.0.1:8000`으로 접속하면 됩니다.

## 현재 한계

- AST는 정규식 기반 fallback 분석기입니다.
- CFG는 MVP 수준의 선형 흐름 분석입니다.
- Verifier는 weighted score 기반입니다.
- 패치 생성은 heuristic + mock/LLM 응답 조합입니다.
- 웹 UI는 MVP이며 인증, 대용량 업로드 제어, 샌드박스 격리는 아직 없습니다.
