# MoneyPrinterTurbo — Codex 구독 OAuth Provider 추가 설계 스펙

> 상태: **Draft (개발 착수 전)**
> 대상 저장소: `harry0703/MoneyPrinterTurbo`
> 참고 구현: `NousResearch/hermes-agent` (MIT License)
> 작성 목적: 구현에 들어가기 전, 통합 지점·인증 흐름·리스크·검증 항목을 합의하기 위한 문서

---

## 0. 한눈에 보기 (TL;DR)

MoneyPrinterTurbo는 현재 LLM provider를 **API 키 방식**으로만 지원한다. 이 문서는 OpenAI **Codex 구독 OAuth**(device-code flow 또는 기존 Codex CLI 토큰 재사용)를 새 provider로 추가하기 위한 사전 설계다.

핵심 결론을 먼저 적는다.

- **기술적으로 가능하다.** Codex가 발급한 OAuth access/refresh 토큰을 Bearer로 사용해 OpenAI Responses API를 호출하면 된다. Hermes가 동일한 방식을 쓰며 코드가 MIT로 공개돼 있어 참고·이식이 가능하다.
- **그러나 약관·정책 리스크가 실재한다.** 구독 요금제는 대화형 사용을 전제로 한 것이며, 자동화 파이프라인(대량 영상 대본 생성)에 붙이는 것은 OpenAI가 명시적으로 허가한 용도가 아닐 수 있다. 사용량 한도(usage limit)에 빠르게 도달하거나 계정 제재 위험이 있다. **이 스펙을 구현하기로 결정하기 전에 §3을 반드시 검토할 것.**
- **이 문서는 "할 수 있는가"가 아니라 "어떻게 안전하고 깔끔하게 붙일 것인가"를 다룬다.** 약관 판단 자체는 사용자/팀의 책임이다.

---

## 1. 배경

### 1.1 현재 MoneyPrinterTurbo의 LLM 연동 방식

> ⚠️ 아래 파일 경로/함수명은 일반적인 구조에 근거한 **추정**이다. 구현 첫 단계에서 실제 코드로 검증해야 한다(§11, OQ-1 참조).

- 설정은 `config.toml`의 `[app]` 섹션에서 `llm_provider`와 provider별 API 키로 관리된다.
- LLM 호출 로직은 `app/services/llm.py` 부근에 집중돼 있는 것으로 보이며, `llm_provider` 값에 따라 분기해 각 provider의 REST 엔드포인트를 호출한다.
- 대본 생성(`generate_script`)과 키워드 생성(`generate_terms`) 정도의 단순 텍스트 호출이 전부다. 즉 **호출당 토큰이 적고 호출 패턴이 단순**하다 — Codex 한도 측면에서는 유리한 편.

### 1.2 Codex OAuth가 일반 API 키와 다른 점

| 구분 | 일반 OpenAI API 키 | Codex 구독 OAuth |
|---|---|---|
| 자격증명 | `sk-...` 정적 키 | access_token + refresh_token (만료/갱신 있음) |
| 발급 경로 | platform.openai.com 대시보드 | OpenAI 웹 로그인 (device-code 또는 브라우저) |
| 과금 | 토큰 사용량별 | 구독에 포함(한도 내) |
| 엔드포인트 | Chat Completions / Responses | 주로 **Responses API** |
| 만료 처리 | 불필요 | **refresh 로직 필수** |

이 차이 때문에 단순히 "키 한 줄 받는" 기존 provider와 달리, **토큰 수명주기 관리**가 추가로 필요하다.

### 1.3 Hermes의 참고 구현 (확인된 사실)

Hermes 문서/이슈에서 확인된 동작:

- provider 식별자는 `openai-codex`이며, `hermes auth add openai-codex` 또는 `hermes model → OpenAI Codex`로 device-code 로그인을 시작한다.
- Hermes가 관리하는 Codex OAuth 자격증명은 `~/.hermes/auth.json`에 저장된다.
- 독립 실행형 Codex CLI로 `codex login`(브라우저 OAuth, localhost 콜백)을 하면 `~/.codex/auth.json`에 유효한 access_token/refresh_token이 저장된다. Hermes는 이 파일을 **import**해서 재사용할 수 있다.
- 토큰 갱신이 종료성 오류(HTTP 4xx, invalid_grant, revoked grant 등)로 실패하면 해당 refresh token을 "죽은 것"으로 표시하고 재시도(replay)를 멈춘다 — 동일 인증 실패 폭주 방지.
- 사용량 한도("usage limit reached")에 도달하면 재시도해도 풀리지 않으므로, 즉시 다른 자격증명으로 전환하는 처리가 들어가 있다.

→ 우리는 이 중 **(a) device-code flow와 (b) `~/.codex/auth.json` import** 두 경로를 모두 후보로 둔다. 구현 우선순위는 §6에서 정한다.

---

## 2. 목표 / 비목표

### 2.1 목표 (Goals)

1. `config.toml`에서 `llm_provider = "openai_codex"`를 선택할 수 있게 한다.
2. 두 가지 자격증명 획득 경로를 지원한다:
   - (우선) 기존 Codex CLI 토큰(`~/.codex/auth.json`) import
   - (차선) device-code OAuth flow 자체 구현
3. access_token 만료 시 refresh_token으로 **자동 갱신**한다.
4. 갱신 불가/한도 도달 시 **명확한 오류 메시지**로 사용자에게 재인증을 안내한다(무한 재시도 금지).
5. 기존 provider 인터페이스를 깨지 않고 **추가만** 한다(하위 호환).

### 2.2 비목표 (Non-goals)

- 여러 Codex 계정 풀(credential pool) 로테이션 — 1차 범위 밖(향후 확장 항목).
- WebUI에서의 OAuth 버튼 흐름 — 1차는 CLI/설정 파일 기준. WebUI 통합은 후속.
- Codex를 대본 외 다른 용도(이미지/음성)에 쓰는 것 — 대상 아님.
- OpenAI 약관 준수 여부에 대한 법적 판단 — 이 문서가 보증하지 않음(§3).

---

## 3. ⚠️ 리스크 및 약관 (의사결정 게이트)

**이 절은 구현 착수 전에 반드시 합의해야 한다.**

### 3.1 약관 리스크

- Codex/ChatGPT **구독은 대화형 사용을 전제**로 가격이 책정돼 있다. 서드파티 도구가 구독 토큰을 끌어다 자동 배치 워크로드에 쓰는 것은 OpenAI가 공식적으로 연 용도가 아닐 수 있다.
- Hermes가 이 방식을 쓴다는 사실이 "모든 서드파티의 모든 용도가 허용된다"는 의미는 **아니다**.
- 최악의 경우 토큰 무효화·계정 제재 가능성이 있다. **사용자 본인의 책임으로 진행해야 한다.**

### 3.2 운영 리스크

- **사용량 한도:** 구독 한도에 도달하면 재시도로 풀리지 않는다. 배치로 여러 영상을 돌리면 빠르게 소진될 수 있다.
- **토큰 만료/회수:** OpenAI 측 정책 변경으로 device-code flow나 토큰 구조가 예고 없이 바뀔 수 있다(비공개 API 의존).
- **유지보수 부담:** 공식 API가 아니므로, 동작이 깨지면 우리가 따라가며 고쳐야 한다.

### 3.3 권장 대안 (참고)

리스크를 감수할 이유가 비용 절감이라면 다음이 더 안전하다:
- **Gemini 무료 등급 API 키** — 가장 쉬운 무료 시작
- **로컬 Ollama** — 비용 0, 약관 무관
- **OpenRouter** — 단일 키로 GPT 포함 다수 모델, 명확한 약관

> **결정 사항(채워 넣을 것):**
> - [ ] 위 리스크를 인지하고 진행하기로 함 (담당: ___, 날짜: ___)
> - [ ] 사용 범위를 개인/비상업으로 한정함
> - [ ] 한도 도달 시 fallback provider를 함께 설정함

---

## 4. 아키텍처 및 통합 지점

### 4.1 신규 모듈

```
app/
└─ services/
   ├─ llm.py                  # (기존) provider 분기에 openai_codex 추가
   └─ codex_oauth/            # (신규)
      ├─ __init__.py
      ├─ auth.py              # 토큰 획득/갱신/저장 로직
      ├─ device_code.py       # device-code flow 구현
      ├─ token_store.py       # 토큰 영속화 + 만료/quarantine 상태
      └─ client.py            # Responses API 호출 래퍼 (Bearer 주입)
```

### 4.2 호출 흐름 (개념도)

```
generate_script() / generate_terms()
        │
        ▼
  llm.py: provider == "openai_codex" ?
        │ yes
        ▼
  codex_oauth.client.chat(messages)
        │
        ├─ token_store.get_valid_access_token()
        │       │  만료됨?
        │       ├─ yes → auth.refresh()  ──실패──▶ quarantine + 재인증 안내(raise)
        │       └─ no  → 사용
        ▼
  POST {responses_endpoint}  (Authorization: Bearer <access_token>)
        │
        ├─ 200 → 텍스트 추출 후 반환
        ├─ 401 → refresh 1회 시도 후 재요청, 또 실패면 재인증 안내
        └─ 429(usage limit) → 재시도 금지, 명확한 한도 초과 오류 반환
```

---

## 5. 설정 (config.toml) 스키마 변경

`[app]` 섹션에 다음을 추가(필드명은 기존 컨벤션에 맞춰 최종 확정):

```toml
[app]
llm_provider = "openai_codex"

[openai_codex]
# 자격증명 획득 방식: "import"(기존 codex CLI 토큰 재사용) 또는 "device_code"
auth_mode = "import"

# import 모드일 때 읽을 경로 (기본값: ~/.codex/auth.json)
codex_auth_path = "~/.codex/auth.json"

# Hermes처럼 자체 보관할 경로
token_store_path = "~/.moneyprinterturbo/codex_auth.json"

# 사용할 모델 식별자 (예시값 — 실제 사용 가능 모델로 검증 필요)
model = "gpt-5.5"

# Responses API 엔드포인트 (검증 필요, OQ-2)
base_url = "https://api.openai.com/v1"
```

> 보안: `token_store_path` 파일은 **0600 권한**으로 저장한다. refresh_token이 들어가므로 절대 로그/리포지토리에 남기지 않는다.

---

## 6. 인증 흐름 상세

### 6.1 경로 A — 기존 Codex CLI 토큰 import (우선 구현)

가장 단순하고 의존성이 적다. 사용자가 이미 `codex login`을 한 상태를 전제로 한다.

1. `codex_auth_path`(`~/.codex/auth.json`) 존재 여부 확인.
2. 파일에서 `access_token`, `refresh_token`, 만료시각(있다면) 파싱.
3. 유효하면 `token_store_path`로 복사·보관하고 사용 시작.
4. 없으면 사용자에게 "`codex login`을 먼저 실행하세요" 안내 후 종료.

> 장점: device-code 구현 불필요. 단점: 사용자가 Codex CLI를 별도로 설치/로그인해야 함.

### 6.2 경로 B — device-code OAuth flow 직접 구현 (차선)

Codex CLI 없이도 동작하게 하려면 device-code flow를 자체 구현한다.

1. device authorization 요청 → `device_code`, `user_code`, `verification_uri`, `interval` 수신.
2. 사용자에게 `verification_uri`와 `user_code`를 터미널에 출력("브라우저에서 이 코드를 입력하세요").
3. `interval` 간격으로 토큰 엔드포인트를 폴링.
   - `authorization_pending` → 계속 폴링
   - `slow_down` → 간격 증가
   - 성공 → `access_token`/`refresh_token` 저장
   - 만료/거부 → 오류 반환
4. 획득한 토큰을 `token_store_path`에 저장.

> ⚠️ device authorization/token 엔드포인트 URL과 client_id는 **공개 문서로 확정되지 않은 비공개 영역**이다. Hermes 소스(`hermes_cli`/auth 관련, MIT)에서 상수를 확인해 이식하되, 변경 가능성을 코드 주석으로 명시한다(OQ-3).

### 6.3 토큰 갱신 (공통)

- 매 호출 전 access_token 만료 여부 확인(만료 시각 또는 401 응답 기준).
- 만료 시 refresh_token으로 갱신 요청 → 새 토큰으로 store 갱신.
- 갱신이 **종료성 오류**(`invalid_grant`, revoked 등)면:
  - 해당 토큰을 **quarantine**(죽은 상태로 표시)하고 재시도 중단.
  - 사용자에게 재인증 안내 메시지 반환(경로 A면 `codex login` 재실행, 경로 B면 device-code 재실행).

---

## 7. LLM 호출 경로 수정 (`llm.py`)

1. `_generate_response()`(또는 provider 분기 지점)에 `elif llm_provider == "openai_codex":` 분기 추가.
2. 해당 분기에서 `codex_oauth.client.chat(...)` 호출.
3. 요청 형식은 **Responses API 스키마**에 맞춘다(Chat Completions와 필드가 다를 수 있음 — OQ-2).
4. 응답에서 텍스트를 추출하는 파서를 Responses API 응답 구조에 맞게 작성.
5. 기존 provider들과 동일한 시그니처(입력 messages → 출력 text)로 맞춰 호출부 변경 최소화.

---

## 8. 에러 처리 매트릭스

| 상황 | HTTP/신호 | 처리 |
|---|---|---|
| access_token 만료 | 401 | refresh 1회 시도 → 성공 시 재요청, 실패 시 재인증 안내 |
| refresh 종료성 실패 | invalid_grant 등 | quarantine, 재시도 금지, 재인증 안내 |
| 사용량 한도 도달 | 429 (usage limit) | **재시도 금지**, "구독 한도 초과" 명확히 안내. fallback provider 있으면 전환 |
| 일시적 429 | 429 (transient) | 짧은 backoff 후 1회 재시도 |
| auth 파일 없음 | - | 인증 안내 후 graceful 종료 |
| 네트워크 오류 | 5xx/timeout | 지수 backoff 재시도(상한 설정) |

원칙: **풀리지 않을 실패를 반복 재시도하지 않는다.** (Hermes의 quarantine 패턴 차용)

---

## 9. 테스트 계획

- **단위 테스트**
  - token_store 저장/로드/권한(0600) 검증
  - 만료 판정 로직(경계값: 만료 직전/직후)
  - refresh 성공/종료성 실패/일시 실패 분기
  - `~/.codex/auth.json` 파싱(정상/누락/손상 케이스)
- **통합 테스트(모킹)**
  - device-code flow 폴링 시퀀스(pending → success)
  - 401 → refresh → 재요청 경로
  - 429 usage limit → 재시도 안 함 확인
- **수동 e2e**
  - 실제 Codex 구독으로 `generate_script` 1회 호출 성공
  - 토큰 만료 강제 후 자동 갱신 확인
- **회귀**
  - 기존 provider(OpenAI API key, Gemini 등)가 영향받지 않는지 확인

> 주의: 실제 토큰을 테스트 픽스처/CI에 넣지 말 것. 통합 테스트는 모킹 기반.

---

## 10. 구현 로드맵 (단계별)

1. **M0 — 검증 스파이크 (0.5d):** 실제 코드로 §1.1 가정 확인, Responses API 엔드포인트/모델/응답 스키마 확인(OQ-1·2·3 해소).
2. **M1 — 경로 A (import) (1d):** `~/.codex/auth.json` import + token_store + 단순 호출. 가장 빠른 동작 검증.
3. **M2 — 갱신/에러 처리 (1d):** refresh, quarantine, 429 처리.
4. **M3 — 경로 B (device-code) (1~2d):** 자체 OAuth flow. 비공개 상수 이식 + 주석.
5. **M4 — config/문서화 (0.5d):** config.example.toml 갱신, README에 리스크 경고 포함.
6. **M5 — 테스트 (1d):** §9.

(추정치이며 OQ 해소 결과에 따라 변동)

---

## 11. 미해결 질문 (Open Questions) — 개발 전 확인 필수

- **OQ-1:** MoneyPrinterTurbo의 실제 LLM 분기 지점은 어디인가? (`app/services/llm.py`의 함수명/시그니처 확인)
- **OQ-2:** Codex 토큰으로 호출하는 정확한 엔드포인트(Chat Completions vs Responses)와 요청/응답 스키마는? 사용 가능한 모델 식별자는?
- **OQ-3:** device-code flow의 authorization/token 엔드포인트 URL과 client_id 상수는? (Hermes 소스에서 확인, 비공개 의존성 명시)
- **OQ-4:** `~/.codex/auth.json`의 실제 필드 구조(키 이름, 만료 표기 방식)는?
- **OQ-5:** 한도 초과 시 fallback provider로 자동 전환할 것인가, 단순 실패시킬 것인가? (정책 결정)
- **OQ-6:** WebUI 통합을 1차 범위에 넣을 것인가, 후속으로 미룰 것인가?

---

## 12. 참고 자료

- 참고 구현: `NousResearch/hermes-agent` (MIT) — `openai-codex` provider, `hermes auth add openai-codex`, `~/.codex/auth.json` import 로직
- 대상: `harry0703/MoneyPrinterTurbo` — `config.toml` provider 설정, `app/services/llm.py`
- 관련 이슈(참고): Hermes #9283 (codex CLI 토큰 import 누락 버그) — import 단계 구현 시 참고

---

## 부록 A — 라이선스 메모

Hermes는 MIT 라이선스이므로 코드 참고·이식이 가능하나, **이식한 부분은 출처와 라이선스 고지를 유지**해야 한다. MoneyPrinterTurbo 또한 MIT이므로 라이선스 충돌은 없으나, 파생 코드에 원 저작권 표시를 남길 것.

## 부록 B — 결정 로그 (Decision Log)

| 날짜 | 결정 | 근거 |
|---|---|---|
| | 진행/보류 여부 (§3 게이트) | |
| | 우선 경로: import vs device-code | |
| | fallback 정책 | |