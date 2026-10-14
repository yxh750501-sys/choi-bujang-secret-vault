# BYTE BACK 방어전 12단계

## 12단계 운영 안내

검사 기준은 `1e06d42f4abb69cad677c159af536d8aa9732553`(11단계 main)입니다. 이 문서의 아래 1~11단계 시험 수치와 단계별 `step` 문장은 당시의 기록이며, 현재 설정은 `aleph.config.json`의 `step: 12`입니다. 현재 공개 앱 주소는 `https://choi-bujang-secret-vault-jade-alpha.vercel.app`이고, 로그인 발급자·JWKS·원본 API 주소·허용 판정 경로는 `aleph.config.json`의 기존 값을 유지합니다.

- 설치: 새 복제본에서 Node.js 22 이상을 준비하고 `npm install`을 실행합니다. 비밀값은 저장소에 넣지 말고 배포 환경의 비밀 입력란에 설정합니다.
- 실행: `npm run build -- --local`은 공개 앱 셸을 빌드하고, `npm test`는 구현된 API·화면을 로컬 테스트에서 실행합니다. 현재 `package.json`에는 로컬 웹 서버 시작 명령이 없습니다.
- 중지: 위 명령은 작업이 끝나면 종료됩니다. 진행 중인 명령은 해당 터미널에서 Ctrl+C로 중단합니다. 서버리스 함수 메모리에 둔 10단계 복구 연습 상태는 함수 재시작 뒤 유지되지 않습니다.
- 복구 연습: `npm run test:stage10`으로 구현된 가상 fixture의 미리보기·복원·재시험을 확인합니다. `POST /api/restore`는 심판 B의 검증된 JWT와 지정된 가상 fixture에 한정되며 운영 DB의 실제 백업 복구가 아닙니다.
- 시험: `npm test`, `npm run detect`, `npm run decider`, `npm run fixture:7`, `npm run build -- --local`, `git diff --check`, `npm run bundle`을 실행합니다. `npm run verify:stage12`는 실제 로컬 API 핸들러 응답만 검증표에 쓰고 미실행 사례는 `NOT_RUN`으로 남깁니다. `npm run bundle`은 깨끗한 커밋과 별도의 무시된 `bundle-notes.json`이 필요하며 외부 요청은 보내지 않습니다.

로그인 후 **탈환 작전실**은 `GET /api/operations` 응답에서 현재 기기 상태와 기록된 시험 수를 표시합니다. 이 경로는 기존 `/api/device` 함수에 연결되므로 함수 수를 늘리지 않습니다. 규칙·탐지·회수의 ALEPH SDP 엔진 운영 판정 자료는 연결되지 않았으므로 `NOT_RUN` 또는 `UNKNOWN`입니다. 복구 버전의 PASS는 학생 구현의 로컬 fixture 미리보기 API 핸들러 응답에만 해당합니다. 검증표의 41종 공격 시험은 공식 목록과 실측 응답이 없어서 모두 `NOT_RUN`입니다. 표의 요청 ID는 실제 로컬 핸들러 요청에 포함한 시험 상관 ID이며 운영 서버가 발급한 ID가 아닙니다. 화면·기록에는 메모 본문, 쿠키, 토큰, 비밀값을 싣지 않습니다.

`src/attack-check.mjs`의 격리 실행 경로를 사용하는 `npm run bundle`은 외부 요청을 보내지 않고 두 항목 모두 `observed: "not_run"`으로 기록합니다. 배포 주소에 대한 실제 점검은 별도 검증이며, 이 미실행 기록은 공식 심판 결과가 아닙니다.

`src/decider.mjs`, `src/detect.mjs`, API, PWA, 검증표와 작전실은 **학생 구현 코드**입니다. `docs/DECIDER_REQUEST.md`와 `docs/DETECT_EVENTS.md`는 제공된 ALEPH SDP 엔진의 요청·사건 계약을 설명합니다. 실제 엔진의 신원 확인, 사건 전달, 회수 집행과 공식 심판 판정은 학생 코드의 로컬 시험 결과로 대체할 수 없습니다.

## 이전 단계 구현 기록

기존 1~10단계의 인증·소유권·복구 기능을 유지하며, 11단계는 설치형 PWA와 서버 측 기기 승인 검사를 추가합니다. `aleph.config.json`의 `step`은 11이며 `public/manifest.webmanifest`와 `public/sw.js`를 통해 설치 안내와 공개 앱 셸의 오프라인 안내를 제공합니다. Service Worker는 인증·기기·메모·복구 API 응답을 캐시하지 않습니다.

## 11단계 기기 승인 보호

- `/api/device`는 검증된 HttpOnly 로그인 세션과 서버 발급 HttpOnly 브라우저 참조 쿠키를 사용합니다. 브라우저가 보낸 `x-device-id`, 설치 상태, 요청 본문의 권한 주장은 신뢰하지 않습니다. 이 쿠키는 브라우저 프로필 참조일 뿐 WebAuthn 또는 물리 기기 증명이 아닙니다.
- 승인 요청은 `POST /api/device`의 `{"action":"request"}`이며 상태는 `pending`으로만 바뀝니다. 일반 학생의 `approve`/`reject` 요청은 거부됩니다. 별도 `GET /api/device-approval`은 승인 대기 요청을 관리자에게 보여주고, `POST /api/device-approval`은 `{ "action": "approve"|"reject", "userId": "...", "deviceRef": "<SHA-256 참조>" }` 요청을 처리합니다. 해당 API는 검증된 로그인 UUID와 활성 `device_approval_admins` 레코드를 확인하고, CSRF/Origin 보호와 상태 전이를 적용합니다. 관리자는 자기 계정의 기기를 승인할 수 없습니다. 승인 취소는 현재 사용자의 승인된 브라우저 참조에 한해 가능합니다.
- 서버 승인 유효기간은 승인 시각부터 30일입니다. 만료됐거나 만료 시각이 없고 잘못된 승인은 `expired`로 처리되어 메모 접근을 막으며 다시 승인 요청을 해야 합니다.
- `/api/notes` 및 `/api/notes/:id`는 사용자 세션, Supabase의 승인 레코드 `approved`, 기존 `owner_id` 조건을 모두 확인합니다. 미승인·취소·조회 실패는 메모 DB 질의 전에 차단됩니다.
- 영속 저장과 변경 감사는 [supabase/migrations/20261014000000_device_approvals.sql](./supabase/migrations/20261014000000_device_approvals.sql)의 `device_approvals`, `device_approval_events`, `device_approval_admins`를 사용합니다. Migration은 운영 DB에 자동 실행되지 않습니다. 운영 관리자를 등록하려면 Supabase Dashboard의 Authentication > Users에서 이미 존재하는 사용자의 UUID를 확인하고, [supabase/bootstrap/device_approval_admin.sql](./supabase/bootstrap/device_approval_admin.sql)의 placeholder를 그 UUID로 바꾼 뒤 SQL Editor에서 수동 실행해야 합니다. 실제 계정 UUID를 코드에 넣거나 공개 API로 관리자 등록을 하지 마세요. 관리자 조회/승인 저장소 오류 시 승인 처리는 fail-closed 됩니다.
- 설치·승인 상태는 독립적입니다. PWA 설치만으로 서버 권한이 바뀌지 않습니다. 로컬 앱 셸만 오프라인에서 열리고 오프라인·승인 불가 시 보호 자료는 표시되지 않습니다.
- 실행: `npm test`, `npm run detect`, `npm run decider`, `npm run fixture:7`, `npm run build -- --local`. 통합 테스트는 실제 `api/device.js`와 `api/notes.js` 핸들러를 검증하지만 Supabase 운영 DB, Vercel 배포 또는 공식 승인자를 검증하지 않습니다.

자료실은 1~10단계의 인증·소유권·기기·자원 구역·로컬 사건 탐지 기능을 유지합니다. 10단계는 운영 복원 기능이 아니라 출처가 명시된 로컬 가상 fixture를 이용하는 복구 절차 연습입니다. `aleph.config.json`의 `step`은 11이며 기존 API와 로그인 설정은 보존했습니다. Production 동작은 별도로 검증해야 합니다. 실제 개인정보, 비밀번호, 토큰, 서버 전용 키를 저장소에 넣지 마세요.

## 10단계 로컬 복구 연습

- 현재 저장소에는 침해 이전임을 입증하는 정책 백업, 백업 저장소, 감사 로그 저장소 또는 공식 복구 관리자 권한 계약이 없습니다. 따라서 `test/fixtures/`의 자료는 이 단계 테스트를 위해 새로 만든 가상 fixture이며, 9단계 기준 커밋을 참고하지만 실제 과거 백업이나 운영 사용자 자료가 아닙니다.
- 정책 fixture는 버전·대상 서비스·생성 provenance를 확인하고, fixture의 canonical JSON SHA-256을 테스트 코드에 고정된 기준값과 비교합니다. 메모 fixture도 동일하게 canonical JSON 해시, 지정 ID·가상 소유자, 본문 SHA-256, 레코드 한 건을 검증합니다. 이 코드는 저장소 내 fixture 변조 탐지용 테스트 신뢰점일 뿐, 운영 백업의 출처나 침해 전 상태를 증명하지 않습니다.
- `npm run test:stage10`은 실제 변경 없는 미리보기와 인메모리 복구를 시험합니다. 선택 대상은 시험 `notes` 정책 하나와 fixture의 가상 메모 ID 하나뿐입니다. 미리보기는 변경 서비스·필드만 보여주며 메모 본문은 출력하지 않습니다. 다른 시험 서비스 정책과 기존 감사 항목은 보존되고, 이미 같은 상태인 반복 복구는 자료를 다시 쓰지 않습니다.
- 정책 복원 시뮬레이션은 fixture 버전 `stage10-safe-policy-fixture-v1`의 `notes` 정책만 적용하고 나머지 서비스를 보존합니다. 메모 시뮬레이션은 ID `623e4567-e89b-42d3-a456-000000000001`, 소유자 `723e4567-e89b-42d3-a456-000000000001`로 고정된 가상 사본 한 건만 적용하고 복구 뒤 ID·소유자·본문 해시를 재검증합니다. 이 ID들은 운영 계정·메모 ID가 아닙니다.
- `restoreRoute`는 `POST /api/restore`이며 Vercel의 `api/restore.js` 서버 함수에 연결됩니다. 복구 요청은 기존 `createLoginVerifier`가 검증한 심판 JWT 중 identity `b`만 허용합니다. 브라우저 세션 쿠키, 학생 토큰, identity `a`, 요청 본문의 role/owner 주장은 권한을 주지 않습니다.
- 요청 JSON은 `{"action":"preview"|"restore","noteId":"623e4567-e89b-42d3-a456-000000000001"}`만 받습니다. 먼저 `action: preview`로 버전과 정책 변경 필드, 가상 메모 ID·소유자·내용 해시를 확인하고, 명시적 `action: restore` 요청에서 다시 검증한 후 처리합니다. `allowedRoutes`는 학습자 메모 판정 경로이므로 기존 `GET /api/notes/:id`를 유지합니다.
- 모든 POST 요청은 신뢰 위치의 가상 fixture 두 파일을 디스크에서 새로 읽어 버전·환경·범위와 코드에 고정된 독립 SHA-256 기준을 확인합니다. 복원 요청은 적용 후보를 만든 다음 fixture를 다시 읽고 해시가 처음 읽기와 같은지 확인한 뒤에만 인메모리 상태를 교체합니다. 파일 누락·변조·버전/범위 오류·읽기 사이 변경은 오류 응답으로 중단하고 상태를 적용하지 않습니다.
- 시험 상태만 서버리스 함수 메모리에 두며 실제 Supabase DB, 운영 정책이나 영속 데이터는 읽거나 변경하지 않습니다. 정확히 지정된 가상 B 메모 한 건만 복구하고 ID·owner ID·본문 SHA-256을 다시 검증합니다. 다른 가상 메모·서비스 정책·기존 감사 항목은 유지하며, 감사에는 본문을 기록하지 않습니다. 이 경로는 운영 복구가 아니며 함수 재시작 뒤 상태가 유지된다고 보장하지 않습니다.
- 복원 POST는 정책·메모 후보를 무결성 확인한 뒤 저장하기 전에 `src/decider.mjs`의 `decide(request)`를 다시 호출합니다. 각 호출은 `docs/DECIDER_REQUEST.md`의 18개 요청 필드만 사용하며, 정상 개별 메모 GET·공지 GET·재인증 후 GET은 `allow`, 미등록 기기·목록·POST/PUT/DELETE·공지 쓰기·강사 자원·추가 인증으로도 금지 쓰기는 `deny`, 복합 이상 요청은 `step_up`이어야 합니다. 별도로 같은 후보 메모 상태에서 ID·소유자·본문 해시와 비대상 정책을 확인합니다.
- A/B 소유권은 기존 `api/notes.js` 핸들러를 호출하고, 그 핸들러에 주입한 인증 mock 및 메모리 클라이언트가 복구 후보의 동일 메모 배열을 읽어 시험합니다. A 자기 메모와 B 자기 메모는 HTTP 200, 서로의 메모는 HTTP 404가 기대값입니다. 이는 `server-mock` 테스트이지 실계정 JWT 검증이나 Production API 호출은 아닙니다. JWT 검증은 복구 POST 자체에서 기존 검증기를 별도로 적용합니다.
- 응답과 추가 감사 항목에는 실행·통과·실패·미실행 건수 및 사례별 기대값/실제 판정·환경을 기록합니다. 미리보기는 `status: not_run`입니다. 사례 예외는 `fail`, 재시험 실행기 예외는 `not_run` 및 상위 `partial`로 기록되며 실패 시 `restored: false`와 HTTP 409를 반환하고 복구 후보를 저장하지 않습니다. 누락·변조 백업은 재시험 전에 중단됩니다.
- 실제 검증 결과: `npm run test:stage10` 15개 통과. 복원 mock POST 한 건에서 복원 뒤 18건(가상 판정기 12, 동일 후보 상태를 읽는 메모 API server-mock 4, 메모/비대상 정책 무결성 2)이 실행되어 **pass 18 / fail 0 / not_run 0**이 응답과 감사에 기록됐습니다. 변조된 금지 요청 응답 주입은 복원을 막았고, 재시험 예외는 pass가 아닌 fail/not_run으로 처리됐습니다. `npm test`와 `npm run test` 각각 48개, 지정 1~9단계 보안 회귀 30개, `npm run detect`, `npm run decider`, `npm run fixture:7`, `npm run build -- --local`, `git diff --check`도 통과했습니다. 탐지·판정 및 재시험은 로컬 가상/mock 검증이지 공식 심판 판정이나 Production 복원이 아닙니다. 의존성 변경이 없어 `npm install`은 다시 실행하지 않았습니다.
- 미검증: 과거 침해 이전 운영 백업, 공식 심판의 실제 요청 본문 계약과 운영 관리자 권한, Production Vercel 함수 런타임의 메모리 지속성, Supabase 실제 메모 복구. 실제 Supabase DB·운영 정책·Vercel Production 배포는 수행하지 않았습니다.

## 9단계 탐지 한계

- 공식 `DETECT_EVENTS` 계약은 `at`, `method`, `identity.sub`만 제공합니다. 현재 연습기는 같은 가명 주체의 GET 사건이 어느 10분 구간에서든 120회를 초과하면 `propose_revocation` / `burst_read`와 해당 주체를 반환하고, 그 외에는 `observe`합니다. 정확히 120회는 관찰 대상입니다.
- 사건 입력은 UTC ISO 시각·GET·비어 있지 않은 가명 주체만 집계합니다. 잘못된 사건은 무시하고 배열이 아닌 최상위 입력은 오류로 처리합니다. 정렬 순서와 무관한 10분 구간 및 경계값을 테스트합니다.
- 계약에는 검증된 기기 ID와 네트워크 이상 신호가 없습니다. 따라서 검증된 새 네트워크와 대량 조회의 복합 조건, 단일 기기를 특정하는 회수 제안, 정상 기기 유지 여부는 구현·검증할 수 없습니다. 현재 계약 그대로면 조회량만으로 주체 단위 제안이 나오므로 목표 요구를 충족했다고 볼 수 없습니다. 네트워크·기기 값은 임의로 만들지 않습니다.
- 이벤트 식별자도 계약에 없어 재전달된 중복 사건과 같은 시각의 서로 다른 조회를 안전하게 구분할 수 없습니다. 중복 제거를 추측해 추가하지 않았습니다.
- `npm run detect` / `npm run detect:test` 및 `npm run decider`, `npm run fixture:7`은 가상 연습입니다. 실제 엔진 사건 전달, 회수 집행, 소요 시간은 연결하거나 측정하지 않았습니다.
- 검증: `npm run detect`, `npm run decider`, `npm run fixture:7`, 지정 회귀 테스트 30개, `npm run build -- --local`, `git diff --check`, 별도 복제본 `npm install`이 통과했습니다.
- 기존 판정기 5필드 응답, 8단계 자원 구역, API 인증·CSRF·소유권 동작은 변경하지 않았습니다. 운영 `reasonCode` 등록, Production 이벤트 전달·복합 신호·회수 집행 및 시간 측정은 미검증입니다.

## 8단계 자원 구역

- 판정기는 계약에 있는 `service`, `method`, `path`, `route`, `queryLength`만 사용합니다. 등록 기기에서 `service: notes`, `GET`, 정확한 `GET /notes/:id` route, 쿼리 없음, 단일 비어 있지 않은 ID 경로만 허용합니다. 메모 ID는 UUID 형식을 강제하지 않습니다.
- 전체 목록, ID 누락, 추가 경로 구간, 퍼센트 인코딩·쿼리 우회, 쓰기 메서드와 미등록 서비스·경로는 `deny` / `resource_access_denied` (`resource_boundary`)입니다. 유효한 추가 인증으로도 이 거부를 바꿀 수 없습니다.
- 가상 판정 예시의 정확한 `announcements` / `GET` / `/announcements` 조합만 허용하며, 쓰기·쿼리·추가 경로·유사 경로는 거부합니다. 이는 예시 요청 판정일 뿐 공식 엔진의 실제 공지 경로나 운영 API 지원을 뜻하지 않습니다. 강사 전용 자료와 기타 미등록 구역은 거부합니다.
- `allowedRoutes`에는 실제 메모 API에 대응하는 판정 정책의 `GET /api/notes/:id`만 둡니다. 공지 API 경로는 운영 계약이 없어 추가하지 않았으며, 이 목록은 Vercel 라우팅 설정이 아닙니다. 기존 실제 메모 CRUD 경로는 그대로 유지됩니다.
- 실제 API의 세션/Bearer 검증, 요청자 역할·`owner_id` 무시, 목록의 서버 검증 사용자 필터와 단건 GET/PUT/DELETE의 검증 사용자 `owner_id` 조건을 재사용했습니다. A/B 사용자 교차 접근은 기존 API 테스트의 404 기대를 유지합니다. 메모 API 파일은 변경하지 않았습니다.
- 검증 결과: `npm run decider`의 가상 판정 34건, `npm run fixture:7`, 지정 회귀 테스트 30개, `npm run build -- --local`, `git diff --check`, 별도 복제본 `npm install`이 통과했습니다. 추적 파일의 비밀 패턴 검사는 기존 `test/r5.test.mjs`의 가상 Bearer fixture 한 건만 탐지했으며 실제 비밀값이 아닙니다. 공개 산출물에서는 패턴이 탐지되지 않았습니다.
- 실제 Supabase 계정·DB, Production 라우팅과 사용자별 메모 접근, 반 공지 및 강사 자료의 운영 API는 확인하지 않았습니다. `npm run decider`와 `npm run fixture:7`은 가상 요청 연습이지 심판 판정이 아닙니다.
- `resource_access_denied`가 운영 등록부의 허용 `reasonCode`인지도 확인하지 않았습니다.

## 현재 동작

- `/`는 Supabase Auth 이메일·비밀번호 로그인/로그아웃과 저장 세션 복원을 표시합니다. 유효한 Access Token이 있는 로그인 상태에서만 메모를 요청·표시하며 로그아웃 또는 401/403 응답이면 메모를 지우고 세션을 종료합니다.
- 브라우저 SDK는 고정된 `@supabase/supabase-js` 2.117.2의 로컬 UMD 파일을 빌드에서 복사합니다. 메모 요청은 실제 SDK 세션 Access Token을 Bearer Authorization으로 전달하며 토큰은 화면이나 로그에 출력하지 않습니다.
- `GET/POST /api/notes`와 `GET/PUT/DELETE /api/notes/:id`는 `src/verify-login.mjs`의 `createLoginVerifier` 결과를 확인한 뒤에만 DB에 접근합니다. 인증만으로 타인의 메모를 읽거나 바꿀 수 있었던 IDOR 문제를 해결하기 위해 서버가 검증한 `identity.userId`를 목록·단건 조회·수정·삭제의 `owner_id` 조건에 적용합니다. 생성 시에도 `owner_id`는 이 검증된 사용자 ID로 지정하며 클라이언트의 같은 이름 필드는 권한 결정에 사용하지 않습니다. 다른 사용자 소유 또는 없는 ID는 같은 `404 NOTE_NOT_FOUND` 응답을 반환합니다. 목록은 `{ notes: [{ id, title, body }] }`, 개별 GET/PUT은 `{ id, title, body }`, POST/DELETE는 `{ id }` 형식을 유지합니다. API의 `body`는 DB `content`에 매핑됩니다. 토큰이 없거나 검증에 실패하면 401 JSON을 반환하고 DB에 접근하지 않습니다.
- 빌드는 `public/data.json`을 만들지 않으며, 이전 로컬 빌드에서 남은 파일도 제거합니다. Vercel의 정적 산출물 경로는 기존처럼 `public`입니다.
- Vercel 배포 빌드는 배포 식별 정보를 `public/aleph.json`에 기록합니다. 실제 Vercel 배포에서만 이 파일의 제공 여부를 확인할 수 있습니다.
- Vercel 응답에는 `X-Content-Type-Options: nosniff` 헤더를 설정합니다.
- 서버 API는 서버 전용 `SUPABASE_SECRET_KEY`를 사용하고, Supabase SDK의 표준 서버용 `createClient` 옵션(`autoRefreshToken: false`, `persistSession: false`)을 사용합니다. 토큰 검증 전에는 메모 테이블을 조회하지 않으며 API 키와 인증 헤더를 응답·로그에 포함하지 않습니다.

로컬 빌드는 `npm run build -- --local`로 확인할 수 있습니다. 로그인 연결을 켜려면 빌드 환경변수 `SUPABASE_URL`과 `SUPABASE_PUBLISHABLE_KEY`를 설정해야 합니다. Publishable Key는 브라우저 설정 파일에 포함되는 공개 값이며 Secret Key가 아닙니다. 값이 없으면 빌드는 성공하고 로그인 UI는 설정 미완료 상태로 표시됩니다.

## Supabase와 환경변수

- Supabase `public.notes`에는 A 소유 가상 메모 4건과 B 소유 가상 메모 1건이 있다고 전달받았습니다. 이 세션에서는 원격 DB 상태를 직접 확인하거나 SQL을 실행하지 않았습니다.
- [supabase/schema.sql](./supabase/schema.sql)은 `public.notes`에 한정해 RLS를 활성화하고 `PUBLIC`, `anon`, `authenticated`의 직접 테이블 권한을 회수하며 `service_role`에 CRUD 권한을 부여합니다. `authenticated`에게는 테이블 CRUD를 부여하지 않습니다. 기존 8개 소유자 정책은 삭제·수정하지 않고, 새 환경에서만 없는 정책을 생성합니다. 다른 테이블, `auth.users`, 메모 행·내용·소유자 정보는 변경하지 않습니다. SQL은 아직 운영 DB에 실행하지 않았습니다. 적용 전에 [supabase/verify.sql](./supabase/verify.sql)로 권한과 정책 수를 확인하고, 기존 메모와 소유자 정보가 보존되는지 별도로 확인하세요.
- Vercel Dashboard의 프로젝트 **Settings → Environment Variables**에서 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 **서버 런타임 환경변수**로 설정한 뒤 재배포합니다. 키 값은 브라우저나 Git에 넣지 마세요.
- 브라우저 Auth를 빌드하려면 `SUPABASE_URL`과 `SUPABASE_PUBLISHABLE_KEY`를 Vercel Production 빌드 환경에도 설정합니다. 실제 Publishable Key는 Supabase Dashboard의 **Project Settings → API Keys**에서 직접 확인하세요. 이 값은 공개되도록 설계된 키입니다.
- Supabase Dashboard의 **Authentication → Providers → Email**에서 이메일 로그인을 활성화하고, 테스트용 가상 계정을 준비하세요. 이메일 확인 설정에 따라 먼저 확인 메일을 완료해야 로그인할 수 있습니다.
- `aleph.config.json`의 issuer와 JWKS URL은 Supabase 프로젝트의 공개 OIDC discovery 문서와 JWKS endpoint에서 확인한 Auth 주소입니다. `audience`는 표준 Supabase Auth Access Token 값인 `authenticated`입니다. 검증 도우미는 비대칭 서명 검증과 Supabase Auth의 `getClaims` 경로를 사용합니다. 현재 확인된 프로젝트 JWKS는 ES256 공개 키를 제공하며, 실제 계정 토큰의 서명·claims 검증은 로그인 테스트 시 확인해야 합니다.
- 함수는 메모 자료의 읽기·쓰기 모두 서버 전용 `SUPABASE_SECRET_KEY`로 수행합니다. `service_role`은 RLS를 우회하므로 각 API 쿼리의 검증된 `identity.userId` 기반 `owner_id` 필터가 접근 경계이며 반드시 유지해야 합니다. `authenticated`의 DB 직접 권한을 제거해도 API의 JWT 검증과 서버 CRUD는 이 키·소유자 필터로 동작합니다.
- 잘못된 입력은 JSON 400, 없는 메모는 JSON 404, DB/설정 오류는 내부 정보를 숨긴 JSON 503으로 처리합니다. 응답은 `Cache-Control: no-store`입니다.

`owner_id`는 UUID 컬럼이며 `auth.users` 외래키가 없습니다. RLS는 `authenticated` 요청에서 `auth.uid()`와 `owner_id`를 비교합니다. 서버 API의 `SUPABASE_SECRET_KEY`/`service_role`은 RLS를 우회할 수 있으므로 각 API 쿼리의 소유자 필터도 반드시 유지해야 합니다. SQL Editor를 관리자 권한으로 사용한 결과만으로는 일반 `authenticated` 사용자의 RLS 제한을 입증할 수 없습니다.

## 5단계 제작 2 확인 사항

- 관련 테스트는 `npm run test:r5 && npm run test:package`로 실행합니다. 테스트는 두 사용자 데이터 분리, 교차 사용자 GET/PUT/DELETE의 404 및 변경 없음, 위조 `owner_id` 무시를 mock DB에서 확인합니다. 실제 Supabase 계정 CRUD와 Production 동작은 별도 확인 전까지 미검증입니다.
- 로컬 공개 빌드는 `npm run build -- --local`로 확인합니다. `public/data.json`을 만들지 않으며, 이전 파일이 있으면 제거합니다. `/aleph.json`은 실제 Vercel 빌드에서 실제 커밋 정보와 `step` 7을 기록합니다.
- DB 권한 SQL은 운영 SQL Editor에서 검토 후 별도로 실행해야 합니다. `supabase/verify.sql`의 `has_table_privilege` 결과에서 anon/authenticated는 CRUD 모두 false, service_role은 모두 true여야 합니다. `information_schema.role_table_grants` 결과도 함께 확인하세요. 이 프로젝트에서는 아직 실행하지 않았습니다.
- 배포 후 `/data.json`은 404, `/aleph.json`의 `step`은 5, 첫 화면은 `nosniff`, 무인증 API는 JSON 401, 각 로그인 계정은 자기 메모 CRUD 성공 및 타인 메모 접근 404여야 합니다.

```sh
APP_URL='https://YOUR_APP.vercel.app'
curl -sS -o /dev/null -w '%{http_code}\n' "$APP_URL/data.json"
curl -fsS "$APP_URL/aleph.json"
curl -fsSI "$APP_URL/" | grep -i '^x-content-type-options:'
curl -i "$APP_URL/api/notes"
```

- API 접근제어는 서버용 `SUPABASE_SECRET_KEY`가 RLS를 우회하더라도 각 쿼리에 소유자 조건을 명시해 적용합니다. 기존 8개 RLS 정책은 보존되며, 권한 회수 후에도 서버 측 소유자 조건을 대체하지 않습니다.
- 수동 확인은 별도의 테스트 계정 A와 B로 로그인해 각자 목록에 자기 메모만 나오는지 확인한 뒤, 상대방 메모의 ID를 API 경로에 지정해 GET/PUT/DELETE가 모두 404이고 데이터가 유지되는지 확인합니다. 토큰과 실제 사용자 메모 본문은 명령 기록이나 저장소에 남기지 마세요.
- `npm run bundle`은 커밋되지 않은 변경과 자리표시자 배포 설정이 있으면 통과하지 않습니다. 유효한 설정을 갖춘 뒤 깨끗한 작업 트리에서 실행하며, 외부 공격 점검은 `not_run`으로 남깁니다.

## 6단계 등록 기기 접근제어

- `src/decider.mjs`의 `device_registered` 규칙은 요청의 `deviceRegistered`가 정확히 `true`일 때만 기기 등록 조건을 통과시킵니다. `false`, 누락, `null` 또는 다른 타입은 `deny`와 `device_not_registered`로 거부합니다.
- 정상 등록 기기 요청은 기존 요청 검증을 전제로 `allow`됩니다. 계약상 의심 신호가 있고 유효한 추가 인증이 없으면 `step_up_required`를 반환합니다. `stepUp.verified === true`는 `authAgeSeconds`가 숫자 정수 0~900일 때만 추가 인증 완료로 인정됩니다. 이 판정기는 계약에 정의되지 않은 사용자·기기·역할 필드를 읽지 않습니다.
- `npm run decider`는 가상 요청으로 등록 기기 허용, 미등록/잘못된 등록 정보 거부, 의심 신호와 추가 인증 조건을 연습합니다. `npm run decider:test`도 같은 검사를 실행합니다. 이는 로컬 가상 연습이며 실제 심판 판정이 아닙니다.
- `aleph.config.json`의 `step`은 6입니다. 별도 프로그램, 인증서 또는 개인키 설치가 필요하지 않습니다. 기존 프로젝트 의존성으로 실행합니다.
- 검증 명령: `npm run decider`. 등록 기기의 정상 요청은 `allow`, 미등록 기기와 등록 정보 누락은 `deny`/`device_not_registered`여야 합니다. 의심 신호의 추가 인증 전 요청은 `step_up`, 계약 범위 안에서 추가 인증이 확인된 요청은 `allow`여야 합니다.

## 7단계 평소와 다른 접속 재확인

- 등록 기기만 기존 판정을 통과합니다. 미등록·누락·잘못된 등록 상태는 추가 인증 여부와 관계없이 `deny`/`device_not_registered`입니다.
- 가상 연습에서 검증 출처가 `judge_fixture`이고 비정상 시간(0~5시 또는 23시), 새로운 네트워크(`unusual`), 최근 5분 내 대량 조회 사건(`risk_signal`, count 10 이상)이 모두 함께 있으면 `step_up`을 요구합니다. 지역 신호만 다른 요청은 거부하지 않으며, 지역 값을 판정 근거로 쓰지 않습니다.
- 판정기는 요청 계약에 명시된 필드만 사용합니다. 현재 실제 경로의 접속 신호 출처는 `none`이고 지역·네트워크는 `unknown`입니다. `judge_fixture` 값은 로컬 가상 연습 전용이며, 브라우저가 보낸 IP·위치·헤더를 신뢰 신호로 승격하지 않습니다.
- 계약에는 엔진 검증 결과인 `stepUp.verified`와 `authAgeSeconds`가 있지만, 실제 재로그인 화면·재인증 처리·자료 접근 차단 연결은 정의되어 있지 않습니다. 로컬 판정 결과만으로 운영 재로그인이나 자료 보호가 작동한다고 주장하지 않습니다.
- 검증 결과: `npm run decider`의 20개 가상 판정, `npm run fixture:7`의 정상 `allow`·복합 이상 `step_up`, 지정된 6개 회귀 테스트 30개, `npm run build -- --local`, `git diff --check`가 통과했습니다. 별도 임시 복제본에서 `npm install`도 성공했습니다. 추적 파일 검사에서 실제 비밀값은 확인되지 않았으며 기존 테스트의 가상 인증 문자열만 패턴에 걸렸습니다.
- 판정기·fixture는 실제 심판 판정이 아닙니다. Production의 사용자 로그인·재로그인, DB 접근 차단 및 배포 동작은 미검증입니다.

## 공개 데이터 검사

이전 `data.json`에서 다섯 메모의 제목·본문 각각을 가져와 아래 검색 명령의 자리표시자에 넣습니다. 명령에 메모 본문을 저장소에 적어 두지 마세요.

```sh
git grep -I -l -- '<기존 메모 제목 또는 본문>'
git grep --cached -I -l -- '<기존 메모 제목 또는 본문>'
git grep -I -l -- '<기존 메모 제목 또는 본문>' HEAD
grep -R -I -l -- '<기존 메모 제목 또는 본문>' public/
grep -R -I -l -E 'sb_secret_[A-Za-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer[[:space:]]+[A-Za-z0-9._~+/-]{16,}' api/ src/ scripts/ test/ package/ public/
git check-ignore -v supabase/private-migration.sql
```

이번 검사에서 현재 작업 트리의 추적 소스와 로컬 공개 산출물에서는 네 메모의 제목·본문이 검색되지 않았고, `public/data.json`도 없습니다. 저장점 커밋 전 `origin/main`은 1단계 커밋이었고, `git grep origin/main`에서 기존 `data.json`, `public/data.json`에 본문이 남아 있는 것이 확인됐습니다. 이 저장점 커밋은 두 파일 삭제를 기록하지만 GitHub 최신 공개 브랜치에는 Push 전까지 반영되지 않습니다. 이전 공개 커밋과 기존 Vercel 배포 이력도 남아 있으며, 이번 검사로 그 이력이 삭제됐다고 주장하지 않습니다.

5단계 변경은 로컬 파일과 SQL 초안에만 반영했습니다. 운영 DB에는 SQL을 실행하지 않았고, Git 커밋·Push·Vercel 배포 및 실제 계정/Production 검증도 하지 않았습니다. 이전 공개 커밋과 배포 이력은 별도로 남아 있습니다.

키 검사는 `sb_secret_` 실키 패턴, 개인키·토큰 패턴을 코드와 공개 빌드 산출물에서 검색합니다. 현재 브라우저 HTML과 공개 빌드에서 키 값은 발견되지 않았습니다. 서버 환경변수 이름만 코드에 있으며 키 값은 저장하지 않습니다. `src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 운영 심판의 판정이 아닙니다.
