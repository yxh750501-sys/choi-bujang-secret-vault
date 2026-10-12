# BYTE BACK 방어전 R5

1단계의 공개 가상 자료실을 만들었고, 현재 `aleph.config.json`은 2단계입니다. 메모는 정적 JSON에서 제거했으며, 서버 API가 Supabase에서 읽습니다. 실제 개인정보, 비밀번호, 토큰, 서버 전용 키를 저장소에 넣지 마세요.

## 현재 동작

- `/`는 `/api/notes`를 호출해 Supabase의 가상 메모를 표시합니다.
- `/api/notes`는 `public.notes`에서 `title`·`content`만 최대 네 건 읽습니다. API는 의도적으로 인증 없이 호출 가능하며, 누구나 네 메모를 읽을 수 있습니다. 2단계 과제의 의도된 취약점입니다.
- 빌드는 `public/data.json`을 만들지 않으며, 이전 로컬 빌드에서 남은 파일도 제거합니다. Vercel의 정적 산출물 경로는 기존처럼 `public`입니다.
- Vercel 배포 빌드는 배포 식별 정보를 `public/aleph.json`에 기록합니다. 실제 Vercel 배포에서만 이 파일의 제공 여부를 확인할 수 있습니다.
- Vercel 응답에는 `X-Content-Type-Options: nosniff` 헤더를 설정합니다.
- 서버 API는 Supabase SDK의 표준 서버용 `createClient` 옵션(`autoRefreshToken: false`, `persistSession: false`)을 사용하며 요청 헤더를 별도 가공하지 않습니다. API 키와 인증 헤더는 Supabase 요청에만 쓰이고 응답·로그에는 포함하지 않습니다.

로컬 정적 빌드는 `npm run build -- --local`로 확인할 수 있습니다. 함수 로컬 실행에는 Vercel 환경과 다음 서버 환경변수가 필요합니다. 이 명령은 실제 배포나 `/aleph.json` 제공 여부를 증명하지 않습니다.

## Supabase와 환경변수

- Supabase의 `public.notes` 테이블과 네 건의 가상 메모는 설정되어 있다고 전달받았습니다. 전달된 검증값은 RLS 활성화, `anon`/`authenticated` SELECT 거부, `service_role` SELECT 허용, 정책 0건, COUNT 4입니다. 이 저장소에서 원격 DB에 재접속해 검증한 것은 아닙니다.
- Vercel Dashboard의 프로젝트 **Settings → Environment Variables**에서 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 **서버 런타임 환경변수**로 설정한 뒤 재배포합니다. 키 값은 브라우저나 Git에 넣지 마세요.
- 함수는 GET만 허용하고, 설정 누락이나 DB 오류에는 상세 내부 정보를 반환하지 않고 `503 NOTES_UNAVAILABLE`을 반환합니다. 응답은 `Cache-Control: no-store`입니다.

`owner_id`는 UUID 컬럼이며 `auth.users` 외래키가 없습니다. Supabase의 RLS와 권한 제한은 유지됩니다. API의 서버 전용 `SUPABASE_SECRET_KEY`만 해당 제한을 우회해 조회합니다.

## 다음 단계와 확인 사항

- 다음 단계에서 로그인·인증을 추가하고, 공개 API의 무인증 조회를 제거해야 합니다.
- 실제 배포 후 아래 검사를 실행합니다. `/data.json`은 404여야 하고, `/aleph.json`은 JSON이어야 하며, 헤더에는 `nosniff`가 있어야 하고, API의 `notes` 개수는 4여야 합니다.

```sh
APP_URL='https://YOUR_APP.vercel.app'
curl -sS -o /dev/null -w '%{http_code}\n' "$APP_URL/data.json"
curl -fsS "$APP_URL/aleph.json"
curl -fsSI "$APP_URL/" | grep -i '^x-content-type-options:'
curl -fsS "$APP_URL/api/notes"
```

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

저장점 준비 중 확인된 GitHub 원격은 `https://github.com/yxh750501-sys/choi-bujang-secret-vault`입니다. 2026-10-12 읽기 전용 Production 확인에서 현재 배포는 아직 1단계였습니다: `/data.json`은 200, `/aleph.json`은 step 1, `/api/notes`는 404였고 첫 화면 응답에서 `nosniff` 헤더가 확인되지 않았습니다. 이 작업에서는 배포하지 않았습니다. 이 저장점의 삭제를 커밋해도 GitHub 공개 브랜치는 Push 전까지 이전 커밋을 계속 가리킵니다.

키 검사는 `sb_secret_` 실키 패턴, 개인키·토큰 패턴을 코드와 공개 빌드 산출물에서 검색합니다. 현재 브라우저 HTML과 공개 빌드에서 키 값은 발견되지 않았습니다. 서버 환경변수 이름만 코드에 있으며 키 값은 저장하지 않습니다. `src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 운영 심판의 판정이 아닙니다.
