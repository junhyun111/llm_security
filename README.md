# ai_vuln_analyzer

C/C++ 소스 코드를 AST와 데이터 흐름으로 분석해 취약점 후보, 패치 제안, 재검증 결과를 생성하는 Python 기반 분석 도구입니다. CLI와 웹 UI를 제공하며, LLM을 사용할 수 없는 경우에도 규칙 기반 정적 분석은 계속 실행됩니다.

## 주요 기능

- tree-sitter 기반 C/C++ AST 분석
- 함수 내부 및 함수 간 taint 추적
- 전역 변수, 구조체 필드, 함수 반환값을 통한 데이터 흐름 연결
- 분기, 반복문, 호출, return을 포함한 경량 CFG 생성
- 포인터 alias를 고려한 Use-After-Free 탐지
- 취약점별 Agent 실행
  - Buffer Overflow / Out-of-Bounds
  - Use-After-Free / Double Free
  - Integer Overflow
  - NULL Pointer Dereference
  - Command Injection
  - Format String
  - Path Traversal
  - Unsafe Input
  - Weak PRNG
  - Off-by-one
- 패치 적용 후 AST 재파싱 및 담당 Agent 재실행
- 여러 패치를 병합한 통합 검증과 충돌 탐지
- C/C++ 컴파일러가 있으면 원본과 패치본 syntax compile 비교
- 정답셋 기반 precision, recall, F1 및 패치 지표 계산

## 요구 사항

- Python 3.11 이상
- 실제 패치 컴파일 검증을 사용할 경우 다음 중 하나
  - Clang
  - GCC
  - Visual Studio C++ Build Tools의 `cl.exe`

컴파일러가 없어도 탐지, 패치 생성, AST 검증, 재탐지는 실행됩니다. 다만 `compile_succeeded`는 `null`로 기록되고 패치는 최종 `verified` 처리되지 않습니다.

## 설치

PowerShell 기준:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev,web,treesitter]"
```

OpenRouter 또는 OpenAI를 사용할 경우:

```powershell
python -m pip install -e ".[dev,web,treesitter,openai]"
```

Anthropic을 사용할 경우:

```powershell
python -m pip install -e ".[dev,web,treesitter,anthropic]"
```

## 설정

설정 우선순위는 다음과 같습니다.

1. 프로젝트 루트의 `project_config.json`
2. 동일한 이름의 환경 변수
3. 코드 기본값

예시는 [project_config.example.json](project_config.example.json)을 참고합니다.

```json
{
  "provider": "openrouter",
  "openrouter_api_key": "sk-or-v1-...",
  "openrouter_model": "provider/model-name",
  "openrouter_base_url": "https://openrouter.ai/api/v1",
  "confidence_threshold": 0.8,
  "llm_max_retries": 2,
  "llm_retry_base_seconds": 1.0,
  "web_host": "127.0.0.1",
  "web_port": 8000,
  "web_max_files": 20,
  "web_max_file_bytes": 10485760,
  "web_max_total_bytes": 52428800,
  "web_max_concurrent_scans": 2
}
```

OpenRouter가 429 또는 일시적 연결 오류를 반환하면 지수 백오프로 재시도합니다. 재시도 이후에도 실패하면 LLM 응답 없이 정적 분석을 완료하고 보고서의 `llm_warning`에 원인을 기록합니다.

API 키가 포함된 실제 `project_config.json`은 외부에 공유하거나 커밋하지 않는 것이 좋습니다.

## CLI 사용

설치 후 파일 또는 디렉터리를 분석합니다.

```powershell
python -m ai_vuln_analyzer.cli scan .\samples --provider mock
```

설정 파일의 provider를 사용하려면 `--provider`를 생략합니다.

```powershell
python -m ai_vuln_analyzer.cli scan .\samples
```

기본 출력 파일은 다음과 같습니다.

- `report.md`
- `report.json`

출력 경로를 직접 지정할 수도 있습니다.

```powershell
python -m ai_vuln_analyzer.cli scan .\samples --output result.md --json-output result.json
```

## 웹 UI

```powershell
python -m ai_vuln_analyzer.cli serve
```

브라우저에서 `http://127.0.0.1:8000`으로 접속합니다.

웹 분석은 별도 프로세스에서 격리되어 실행됩니다. 기본 제한은 다음과 같습니다.

- 파일 수: 20개
- 파일당 크기: 10 MiB
- 전체 업로드 크기: 50 MiB
- 동시 분석: 2개
- 분석 timeout: 없음

웹에서는 `.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hh`, `.hpp`, `.hxx` 파일만 허용합니다. 경로가 포함된 파일명, 중복 파일명 및 ZIP 파일은 받지 않습니다.

## 정답셋 평가

분석 결과 JSON과 정답 JSON을 비교합니다.

```powershell
python -m ai_vuln_analyzer.cli evaluate report.json ground_truth.json
```

평가 결과를 파일로 저장하려면:

```powershell
python -m ai_vuln_analyzer.cli evaluate report.json ground_truth.json --output metrics.json
```

정답셋 형식:

```json
{
  "findings": [
    {
      "file": "sample.c",
      "function": "run_admin_task",
      "line": 42,
      "cwe": "CWE-78"
    }
  ]
}
```

평가기는 다음 지표를 계산합니다.

- TP, FP, FN
- Precision, Recall, F1
- CWE 분류 정확도
- 패치 파싱 성공률
- 패치 검증률
- 패치 후 재탐지율

기본적으로 정답 위치에서 앞뒤 1줄까지 동일 위치로 간주합니다. `--line-tolerance`로 조정할 수 있습니다.

## 패치 검증 상태

개별 패치는 다음 조건을 검사합니다.

1. 원본 위치에 패치를 실제 적용할 수 있는가
2. tree-sitter 파싱에 성공하는가
3. 원본에 없던 임의 식별자를 도입하지 않는가
4. 담당 Agent 재실행에서 취약점이 사라지는가
5. 컴파일러가 있다면 syntax compile에 성공하는가

통합 검증은 자동 패치를 하나의 프로젝트 복사본에 병합합니다. 수정 범위가 겹치면서 서로 다른 코드를 제안하면 충돌로 기록하고 해당 패치를 적용하지 않습니다.

`verified`는 파싱, 컴파일, 재탐지 검사가 모두 통과한 경우에만 설정됩니다. 컴파일러가 없거나 원본 프로젝트 자체가 컴파일되지 않으면 `unresolved` 또는 `inconclusive` 결과가 나올 수 있습니다.

## 테스트

```powershell
python -m pytest -q
```

## 현재 한계

- CFG와 alias 분석은 완전한 symbolic execution이 아닌 보수적인 정적 분석입니다.
- 함수 포인터, 복잡한 C++ 템플릿, 동적 디스패치 및 매크로에 의해 생성된 흐름은 일부 놓칠 수 있습니다.
- 실제 빌드 옵션과 include 경로는 아직 `compile_commands.json` 또는 CMake에서 자동으로 가져오지 않습니다.
- Command Injection과 Path Traversal처럼 문맥별 정책이 필요한 취약점은 자동 패치 대신 수동 검토로 남을 수 있습니다.
- 외부에 공개되는 웹 서비스로 운영하려면 인증, reverse proxy 수준의 요청 제한과 운영 모니터링을 추가해야 합니다.
