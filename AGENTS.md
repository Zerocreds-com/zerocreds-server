# Repository instructions

AGENTS.md — короткая точка входа. Основные инструкции, команды, среды и порядок deploy описаны в [README.md](README.md); здесь не дублируются.

## Credentials

Используйте macOS Keychain; секреты не печатаются и не попадают в файлы:
- GitHub default PAT: service `github.com`, account `kobzevvv`, item `Trained Agent GitHub Token`.
- Azure Cloud / GHA / `zen-rings` PAT: service `github.com`, account `gha-compute-cluster`.
- Cloudflare sandbox token: service `cloudflare.com`, account `trained-assist-sandbox`, expected account `d740a05e9442c1d0feacae2dfc673e93`.

## Sandbox / deploy

Порядок sandbox, проверок, deploy и rollback берётся из README.md и referenced docs/workflows этого репозитория.
После merge нельзя считать задачу завершённой без deploy/verify по этому порядку.
Самые опасные изменения — запреты/ограничения прав; они требуют собранного evidence.
