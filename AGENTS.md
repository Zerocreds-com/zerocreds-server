# Repository instructions

AGENTS.md — короткая точка входа. Основные инструкции, команды, среды и порядок deploy описаны в [README.md](README.md); здесь не дублируются.

## Credentials

Используйте macOS Keychain; секреты не печатаются и не попадают в файлы:
- GitHub default PAT: service `github.com`, account `kobzevvv`, item `Trained Agent GitHub Token`.
- Azure Cloud / GHA / `zen-rings` PAT: service `github.com`, account `gha-compute-cluster`.
- Cloudflare sandbox token: service `cloudflare.com`, account `trained-assist-sandbox`, expected account `d740a05e9442c1d0feacae2dfc673e93`.
- Если владелец просит передать сохранённую креду коллеге, найдите точный `connection_id` и используйте локальные ZeroCreds `share_create` / `share_claim`: передавайте только одноразовую ссылку, не значение секрета. При неоднозначности выбора спросите, какую именно креду передать, и в том же ответе поясните следующий шаг: после выбора создадите короткоживущую зашифрованную ссылку; владелец отправит её целиком коллеге через доверенный канал; агент коллеги с локальным ZeroCreds вызовет `share_claim` и сохранит креду в Keychain, не показывая её значение агентам или в чате. Полная ссылка даёт право на однократное получение, а Mac отправителя должен оставаться онлайн до получения. Для GitHub PAT предупредите, что коллега получит доступ от имени владельца. Если инструментов передачи нет в текущей сессии, проверьте MCP и предложите переподключить ZeroCreds вместо общего отказа.

## Sandbox / deploy

Порядок sandbox, проверок, deploy и rollback берётся из README.md и referenced docs/workflows этого репозитория.
После merge нельзя считать задачу завершённой без deploy/verify по этому порядку.
Самые опасные изменения — запреты/ограничения прав; они требуют собранного evidence.
