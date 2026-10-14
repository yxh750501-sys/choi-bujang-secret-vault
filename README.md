# BYTE BACK 방어전 7단계

자료실은 BYTE BACK 5단계 제작 2의 인증·소유권 보호와 6단계 등록 기기 접근제어를 유지하고, 7단계의 가상 이상 접속 추가 확인 판정을 구현했습니다. 메모 접근은 Vercel 서버 API로 모으며 `aleph.config.json`의 `step`은 7입니다. `originalApiUrl`은 원본 Supabase notes REST Data API를 가리킵니다. Production은 별도로 검증해야 합니다. 실제 개인정보, 비밀번호, 토큰, 서버 전용 키를 저장소에 넣지 마세요.

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
- `npm run bundle`은 커밋되지 않은 변경, 자리표시자 배포 설정, 실제 공격 점검 응답이 있으면 통과하지 않습니다. 유효한 설정과 배포를 갖춘 뒤 깨끗한 작업 트리에서 실행합니다.

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
