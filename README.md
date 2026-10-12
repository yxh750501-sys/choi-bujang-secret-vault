# BYTE BACK 방어전 R5

자료실은 BYTE BACK 3단계 제작 3 기준으로 설정되어 있습니다. 브라우저 로그인·로그아웃, 서버 Supabase Access Token 검증 및 인증된 메모 CRUD 경로를 구현했고 `aleph.config.json`의 `step`은 3입니다. 이 변경은 Production에서 검증하지 않았습니다. 실제 개인정보, 비밀번호, 토큰, 서버 전용 키를 저장소에 넣지 마세요.

## 현재 동작

- `/`는 Supabase Auth 이메일·비밀번호 로그인/로그아웃과 저장 세션 복원을 표시합니다. 유효한 Access Token이 있는 로그인 상태에서만 메모를 요청·표시하며 로그아웃 또는 401/403 응답이면 메모를 지우고 세션을 종료합니다.
- 브라우저 SDK는 고정된 `@supabase/supabase-js` 2.117.2의 로컬 UMD 파일을 빌드에서 복사합니다. 메모 요청은 실제 SDK 세션 Access Token을 Bearer Authorization으로 전달하며 토큰은 화면이나 로그에 출력하지 않습니다.
- `GET/POST /api/notes`와 `GET/PUT/DELETE /api/notes/:id`는 `src/verify-login.mjs`의 `createLoginVerifier` 결과를 확인한 뒤에만 DB에 접근합니다. 목록은 `{ notes: [{ id, title, body }] }`, 개별 GET/PUT은 `{ id, title, body }`, POST/DELETE는 `{ id }`를 반환합니다. 생성 시 `body`는 DB `content`로 저장되고 `owner_id`는 검증된 사용자 ID로 기록됩니다. 토큰이 없거나 검증에 실패하면 401 JSON을 반환하고 DB에 접근하지 않습니다. 이 단계에서는 소유자별 접근 제한을 구현하지 않습니다.
- 빌드는 `public/data.json`을 만들지 않으며, 이전 로컬 빌드에서 남은 파일도 제거합니다. Vercel의 정적 산출물 경로는 기존처럼 `public`입니다.
- Vercel 배포 빌드는 배포 식별 정보를 `public/aleph.json`에 기록합니다. 실제 Vercel 배포에서만 이 파일의 제공 여부를 확인할 수 있습니다.
- Vercel 응답에는 `X-Content-Type-Options: nosniff` 헤더를 설정합니다.
- 서버 API는 서버 전용 `SUPABASE_SECRET_KEY`를 사용하고, Supabase SDK의 표준 서버용 `createClient` 옵션(`autoRefreshToken: false`, `persistSession: false`)을 사용합니다. 토큰 검증 전에는 메모 테이블을 조회하지 않으며 API 키와 인증 헤더를 응답·로그에 포함하지 않습니다.

로컬 빌드는 `npm run build -- --local`로 확인할 수 있습니다. 로그인 연결을 켜려면 빌드 환경변수 `SUPABASE_URL`과 `SUPABASE_PUBLISHABLE_KEY`를 설정해야 합니다. Publishable Key는 브라우저 설정 파일에 포함되는 공개 값이며 Secret Key가 아닙니다. 값이 없으면 빌드는 성공하고 로그인 UI는 설정 미완료 상태로 표시됩니다.

## Supabase와 환경변수

- Supabase의 `public.notes` 테이블과 네 건의 가상 메모는 설정되어 있다고 전달받았습니다. 전달된 기존 검증값은 RLS 활성화, `anon`/`authenticated` SELECT 거부, `service_role` SELECT 허용, 정책 0건, COUNT 4입니다. 이 저장소에서 원격 DB의 CRUD 권한을 확인한 것은 아니므로 아래 SQL 권한 변경을 적용하고 별도로 확인해야 합니다.
- Vercel Dashboard의 프로젝트 **Settings → Environment Variables**에서 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 **서버 런타임 환경변수**로 설정한 뒤 재배포합니다. 키 값은 브라우저나 Git에 넣지 마세요.
- 브라우저 Auth를 빌드하려면 `SUPABASE_URL`과 `SUPABASE_PUBLISHABLE_KEY`를 Vercel Production 빌드 환경에도 설정합니다. 실제 Publishable Key는 Supabase Dashboard의 **Project Settings → API Keys**에서 직접 확인하세요. 이 값은 공개되도록 설계된 키입니다.
- Supabase Dashboard의 **Authentication → Providers → Email**에서 이메일 로그인을 활성화하고, 테스트용 가상 계정을 준비하세요. 이메일 확인 설정에 따라 먼저 확인 메일을 완료해야 로그인할 수 있습니다.
- `aleph.config.json`의 issuer와 JWKS URL은 Supabase 프로젝트의 공개 OIDC discovery 문서와 JWKS endpoint에서 확인한 Auth 주소입니다. `audience`는 표준 Supabase Auth Access Token 값인 `authenticated`입니다. 검증 도우미는 비대칭 서명 검증과 Supabase Auth의 `getClaims` 경로를 사용합니다. 현재 확인된 프로젝트 JWKS는 ES256 공개 키를 제공하며, 실제 계정 토큰의 서명·claims 검증은 로그인 테스트 시 확인해야 합니다.
- 함수는 메모 자료의 읽기·쓰기 모두 서버 전용 `SUPABASE_SECRET_KEY`로 수행합니다. `supabase/schema.sql`에는 `service_role`의 SELECT/INSERT/UPDATE/DELETE 권한이 포함됩니다. 기존 DB에 이 권한이 적용되지 않았다면 Supabase Dashboard의 **SQL Editor**에서 해당 grant를 적용해야 합니다. `anon`/`authenticated` 권한 회수와 RLS는 유지합니다.
- 잘못된 입력은 JSON 400, 없는 메모는 JSON 404, DB/설정 오류는 내부 정보를 숨긴 JSON 503으로 처리합니다. 응답은 `Cache-Control: no-store`입니다.

`owner_id`는 UUID 컬럼이며 `auth.users` 외래키가 없습니다. Supabase의 RLS와 권한 제한은 유지됩니다. API의 서버 전용 `SUPABASE_SECRET_KEY`만 해당 제한을 우회해 조회합니다.

## 3단계 제작 3 확인 사항

- 관련 테스트는 `node --test test/*.test.mjs` 또는 `npm run test:r5 && npm run test:package`로 실행합니다. 3단계의 자체 점검은 `/data.json` 비공개와 무인증 `/api/notes`의 JSON 거부를 확인하며, 실제 Supabase 계정 CRUD·Production 동작은 별도 확인 전까지 미검증입니다.
- 배포 후 `/data.json`은 404, `/aleph.json`의 `step`은 3, 첫 화면은 `nosniff`, 무인증 API는 JSON 401, 로그인 계정은 CRUD 성공이어야 합니다.

```sh
APP_URL='https://YOUR_APP.vercel.app'
curl -sS -o /dev/null -w '%{http_code}\n' "$APP_URL/data.json"
curl -fsS "$APP_URL/aleph.json"
curl -fsSI "$APP_URL/" | grep -i '^x-content-type-options:'
curl -i "$APP_URL/api/notes"
```

- 기존 DB에서 CRUD 권한이 아직 부여되지 않았다면 Supabase SQL Editor에서 `supabase/schema.sql`의 `grant select, insert, update, delete on table public.notes to service_role;`를 실행하세요. 기존 네 메모는 이 작업이 삭제하거나 재생성하지 않습니다.
- 4단계에 해당하는 `owner_id`별 접근 제한은 아직 의도적으로 추가하지 않았습니다. 인증된 계정 A의 메모 조회는 유지됩니다.
- `npm run bundle`은 커밋되지 않은 변경, 자리표시자 배포 설정, 실제 공격 점검 응답이 있으면 통과하지 않습니다. 유효한 설정과 배포를 갖춘 뒤 깨끗한 작업 트리에서 실행합니다.

## 공개 데이터 검사

이전 `data.json`에서 네 메모의 제목·본문 각각을 가져와 아래 검색 명령의 자리표시자에 넣습니다. 명령에 메모 본문을 저장소에 적어 두지 마세요.

```sh
git grep -I -l -- '<기존 메모 제목 또는 본문>'
git grep --cached -I -l -- '<기존 메모 제목 또는 본문>'
git grep -I -l -- '<기존 메모 제목 또는 본문>' HEAD
grep -R -I -l -- '<기존 메모 제목 또는 본문>' public/
grep -R -I -l -E 'sb_secret_[A-Za-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer[[:space:]]+[A-Za-z0-9._~+/-]{16,}' api/ src/ scripts/ test/ package/ public/
git check-ignore -v supabase/private-migration.sql
```

이번 검사에서 현재 작업 트리의 추적 소스와 로컬 공개 산출물에서는 네 메모의 제목·본문이 검색되지 않았고, `public/data.json`도 없습니다. 저장점 커밋 전 `origin/main`은 1단계 커밋이었고, `git grep origin/main`에서 기존 `data.json`, `public/data.json`에 본문이 남아 있는 것이 확인됐습니다. 이 저장점 커밋은 두 파일 삭제를 기록하지만 GitHub 최신 공개 브랜치에는 Push 전까지 반영되지 않습니다. 이전 공개 커밋과 기존 Vercel 배포 이력도 남아 있으며, 이번 검사로 그 이력이 삭제됐다고 주장하지 않습니다.

과거에 확인했던 Production은 2단계 상태였습니다. 이번 제작 3의 인증된 CRUD 기능과 DB 쓰기 권한은 로컬 코드 변경이며 Production 배포나 실제 계정으로 검증하지 않았습니다. 이전 공개 커밋과 배포 이력은 남아 있습니다.

키 검사는 `sb_secret_` 실키 패턴, 개인키·토큰 패턴을 코드와 공개 빌드 산출물에서 검색합니다. 현재 브라우저 HTML과 공개 빌드에서 키 값은 발견되지 않았습니다. 서버 환경변수 이름만 코드에 있으며 키 값은 저장하지 않습니다. `src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 운영 심판의 판정이 아닙니다.
