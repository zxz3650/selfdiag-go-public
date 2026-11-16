# 수집·탐지 기능 검증

검증일: 2026-11-16
대상 커밋: `90efc4f4aa1c9acd2aaa0af84e01f886de92052f`
환경: Linux amd64, Go 1.24.0

## 실행 결과

| 명령 | 결과 |
|---|---|
| `go test ./...` | 통과 |
| `go vet ./...` | 통과 |
| `go test -race ./...` | 통과 |
| `sh scripts/build.sh` | linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 빌드 성공 |

`collector`, `detector`, `evidence`, `report` 패키지의 테스트를 실행했습니다. macOS 항목은 크로스 빌드 결과이며 macOS 호스트에서 수집 명령을 실행한 결과와 구분합니다.

## 코드 대응 확인

기존 저장소의 `selfdiag-go/` 하위 경로와 대조해 공개 저장소의 코드·테스트·프로파일·빌드 스크립트 20개 파일이 동일함을 Git blob SHA로 확인했습니다. README와 .gitignore는 공개 저장소에 맞게 다릅니다.
