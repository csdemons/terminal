# rrcki-x2gobroker — лёгкий брокер сессий X2Go

Брокер принимает вход из X2Go Client, проверяет пароль в AD и отправляет пользователя
на узел фермы: в его существующую сессию, если она жива, иначе на самый свободный узел.
Узлы разбиты на пулы (рабочий стол, 1С Бухгалтерия, 1С Документооборот...): у каждого
пула свои машины и своя группа AD, и пользователь попадает только в пулы своих групп.
Упавшие и выведенные на обслуживание узлы обходит. Панель `/admin` показывает,
кто где работает, и позволяет управлять узлами и сессиями в рамках роли.
Все входы, отказы и действия пишутся в журнал аудита с цепочкой хешей.

```
X2Go Client ──HTTPS──▶ nginx ──▶ брокер ──SSH (только агент)──▶ узлы term-NN
     │                              │
     │                              └── LDAPS ──▶ AD (dc1, dc2)
     └──────────── SSH-сессия X2Go напрямую на выбранный узел ──────────────▶
```

Брокер в трафике сессий не участвует: клиент получает имя узла и подключается к нему сам.
Вход на узел идёт с тем же доменным паролем (`usebrokerpass=true` в профиле), поэтому
брокеру не нужны права раскладывать ключи пользователей на узлах.

## Состав

| Файл | Куда |
|---|---|
| `broker/rrcki_x2gobroker.py`, `broker/admin.html` | брокер: `/opt/rrcki-x2gobroker/` |
| `etc/broker.toml.example` | брокер: `/etc/rrcki-x2gobroker/broker.toml` |
| `deploy/rrcki-x2gobroker.service` | брокер: `/etc/systemd/system/` |
| `deploy/nginx-x2gobroker.conf` | брокер: `/etc/nginx/sites-available/x2gobroker` |
| `node/x2go-node-agent` | каждый узел: `/usr/local/sbin/x2go-node-agent` |
| `node/sudoers.d-x2go-node-agent` | каждый узел: `/etc/sudoers.d/x2go-node-agent` |
| `node/authorized_keys.example` | каждый узел: `/home/x2gobroker/.ssh/authorized_keys` |
| `node/1c-launcher.example` | узлы пулов 1С: `/usr/local/bin/1c-buh`, `/usr/local/bin/1c-doc` |
| `tests/` | имитация фермы и сквозной тест: `python3 tests/test_broker.py` |

Зависимости: Python 3.11+ (в Astra 1.8 есть) и `python3-ldap3`. Больше ничего: веб-сервер
и опрос узлов на стандартной библиотеке, SSH — системный клиент.

## 1. ВМ брокера (Astra 1.8)

Отдельная ВМ, например `x2gobroker-01.rrcki.ru`. Вводить в домен не обязательно:
брокер ходит в AD сам по LDAPS.

```bash
apt install python3-ldap3 nginx openssh-client
# если python3-ldap3 нет в репозиториях Astra — взять .deb из Debian bookworm
# тем же способом с pinning, что и раньше (пакет чисто питоновский)

useradd --system --home-dir /var/lib/rrcki-x2gobroker --shell /usr/sbin/nologin x2gobroker
install -d -o root -g root /opt/rrcki-x2gobroker
install -m 0755 broker/rrcki_x2gobroker.py /opt/rrcki-x2gobroker/
install -m 0644 broker/admin.html          /opt/rrcki-x2gobroker/
install -d -m 0750 -o root -g x2gobroker /etc/rrcki-x2gobroker
install -m 0640 -o root -g x2gobroker etc/broker.toml.example /etc/rrcki-x2gobroker/broker.toml

# ключ, которым брокер ходит к агентам узлов
ssh-keygen -t ed25519 -N '' -C rrcki-x2gobroker -f /etc/rrcki-x2gobroker/node_key
chown x2gobroker:x2gobroker /etc/rrcki-x2gobroker/node_key
cat /etc/rrcki-x2gobroker/node_key.pub      # понадобится на узлах
```

Отредактируйте `/etc/rrcki-x2gobroker/broker.toml`: контроллеры домена, путь к корневому
сертификату домена (`ca_file`), узлы, пулы с их группами и профилями, группы ролей панели.
Подробно — разделы «Пулы» и «Роли» ниже.

Проверка связи с AD и ролей конкретного человека:

```bash
sudo -u x2gobroker python3 /opt/rrcki-x2gobroker/rrcki_x2gobroker.py \
     -c /etc/rrcki-x2gobroker/broker.toml --check-login ivanov
```

## 2. Каждый узел фермы

```bash
useradd --system --create-home --shell /bin/sh x2gobroker
install -m 0755 node/x2go-node-agent /usr/local/sbin/x2go-node-agent
install -m 0440 node/sudoers.d-x2go-node-agent /etc/sudoers.d/x2go-node-agent
visudo -cf /etc/sudoers.d/x2go-node-agent

install -d -m 0700 -o x2gobroker -g x2gobroker /home/x2gobroker/.ssh
# строка из node/authorized_keys.example: подставить ключ брокера и IP брокеров
editor /home/x2gobroker/.ssh/authorized_keys
chown x2gobroker:x2gobroker /home/x2gobroker/.ssh/authorized_keys
chmod 0600 /home/x2gobroker/.ssh/authorized_keys

/usr/local/sbin/x2go-node-agent status     # должен вывести JSON с "ok": true
```

Если в `sshd_config` есть `AllowGroups`/`AllowUsers`, добавьте туда `x2gobroker`.
Ключ в `authorized_keys` ограничен `restrict` и forced command: им нельзя получить shell,
только вызвать агента, а агент выполняет лишь `status`, `suspend <sid>`, `terminate <sid>`
и сам определяет владельца сессии.

## 3. Связать брокер с узлами и запустить

На брокере:

```bash
ssh-keyscan term-01.rrcki.ru >> /etc/rrcki-x2gobroker/known_hosts
chown root:x2gobroker /etc/rrcki-x2gobroker/known_hosts; chmod 0644 /etc/rrcki-x2gobroker/known_hosts

sudo -u x2gobroker python3 /opt/rrcki-x2gobroker/rrcki_x2gobroker.py \
     -c /etc/rrcki-x2gobroker/broker.toml --check-nodes

install -m 0644 deploy/rrcki-x2gobroker.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now rrcki-x2gobroker
journalctl -u rrcki-x2gobroker -f
```

nginx: положите сертификат `x2go.rrcki.ru`, поправьте в `deploy/nginx-x2gobroker.conf`
пути и сеть администраторов в `location /admin`, затем:

```bash
cp deploy/nginx-x2gobroker.conf /etc/nginx/sites-available/x2gobroker
ln -s ../sites-available/x2gobroker /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

## 4. Клиент

```
x2goclient --broker-url=https://x2go.rrcki.ru/ --broker-name="РРЦКИ" --no-session-edit
```

Пользователь вводит доменный логин (`ivanov`, `RRCKI\ivanov` или `ivanov@rrcki.ru` —
всё приводится к `ivanov`) и пароль один раз.

## Пулы

Пул — набор машин под одну задачу. Пример из `etc/broker.toml.example`:

| Пул | Узлы | Группа AD | Что видит пользователь |
|---|---|---|---|
| `desktop` | term-01 | grp-x2go-desktop | полный рабочий стол MATE |
| `1c-buh` | term-buh-01, term-buh-02 | grp-1c-buh | только окно 1С Бухгалтерии |
| `1c-doc` | term-doc-01 | grp-1c-doc | только окно 1С Документооборота |

* В клиенте пользователь видит по профилю на каждый пул, в группе которого состоит.
  Бухгалтер видит один профиль «1С Бухгалтерия»; человек из обеих групп 1С — два.
* Профиль пула ведёт только на узлы этого пула. Подставить чужой пул, отредактировав
  запрос, нельзя: брокер проверяет группу при каждом входе, и попытка пишется в аудит.
* Сессии разных пулов независимы: открытая Бухгалтерия не мешает войти в Документооборот,
  возврат в приостановленную сессию — в пределах своего пула.
* Нагрузка считается внутри пула: если Документооборот заполнен, пользователь получит
  отказ, даже если в Бухгалтерии места есть, — машины пулов могут отличаться ПО и базами.
* Узел входит ровно в один пул; брокер не запустится с узлом в двух пулах или вне пулов.
* `rootless = true` и `command` с путём к программе превращают пул в опубликованное
  приложение: пользователь видит только окно 1С, а при закрытии 1С сессия завершается.
  Обёртка с подключением к нужной базе — `node/1c-launcher.example`.
* В панели узлы сгруппированы по пулам со свободными местами каждого, у сессий указан пул,
  есть фильтр по пулу.

Чтобы добавить пул, опишите его узлы в `[[nodes]]`, сам пул в `[[pools]]`, создайте
группу AD и перезапустите брокер. Добавить узел в существующий пул — дописать его в
`[[nodes]]` и в `nodes` пула.

## Роли

Каждой роли соответствует группа AD в `[auth.roles]`. Роли суммируются.

| Право | viewer | officer | admin | security |
|---|:-:|:-:|:-:|:-:|
| Видеть узлы, сессии, оперативный журнал | ✓ | ✓ | ✓ | ✓ |
| Приостановить, завершить, сбросить сессию пользователя | | ✓ | ✓ | |
| Вывести узел на обслуживание и вернуть | | | ✓ | |
| Журнал аудита: просмотр, проверка целостности, выгрузка CSV | | | | ✓ |
| Снять блокировку входа после перебора паролей | | | | ✓ |

Роль панели не даёт входа на ферму (для этого нужна группа пула), и наоборот.

Администратор не видит и не выгружает журнал аудита, безопасность не управляет фермой:
так действия администратора контролирует независимая сторона. Попытка открыть то, на что
нет права, отклоняется и сама попадает в аудит.

## Журнал аудита

`/var/log/rrcki-x2gobroker/audit.jsonl`, одна JSON-запись в строке. Пишется:

* `auth.ok`, `auth.fail`, `auth.lockout`, `auth.blocked`, `auth.error` — входы и пароли
  (клиент X2Go, панель, консоль); вход в панель — не чаще раза в 30 минут на человека;
* `access.denied` — нет группы доступа или нет права на действие;
* `broker.route`, `broker.no_capacity` — куда направлен пользователь и почему;
* `session.suspend|terminate|forget` — кто, с чьей сессией, на каком узле, итог;
* `node.drain|undrain`, `security.unlock`, `audit.export`, `service.start`.

Каждая запись содержит хеш предыдущей. Правка, удаление или вставка записи в середине
обнаруживаются:

```bash
python3 /opt/rrcki-x2gobroker/rrcki_x2gobroker.py --verify-audit
```

Тот же результат показывает панель безопасности. Цепочка не защищает от того, кто
имеет root на ВМ брокера и пересчитает все хеши: для этого каждая запись дублируется
в syslog (логгер `x2gobroker.audit`), откуда её нужно забирать в SIEM или на
центральный сервер журналов. Файл не ротируйте logrotate'ом: при ~200 пользователях
он растёт на единицы мегабайт в год; при архивировании начните новый файл, а проверка
примет первую запись нового файла как продолжение архивного.

## Как брокер выбирает узел

Всё ниже — в пределах пула, который пользователь выбрал в клиенте.

1. Есть живая сессия пользователя в этом пуле → тот же узел (сначала приостановленная,
   затем активная, самая свежая). Это работает и для узла на обслуживании.
2. Иначе среди узлов пула «в строю», не на обслуживании, с запасом памяти не ниже
   `min_free_mem_percent` и с местом до `max_sessions` выбирается узел с наименьшим
   `(сессии + резервы) / (max_sessions × weight) + load_weight × загрузка CPU`.
3. Выбранное место резервируется за пользователем на `reserve_seconds`, пока его сессия
   не появится в опросе, — утренний наплыв не уходит весь на один узел.
4. Свободных узлов нет → клиент получает ошибку «No free terminal servers».

## Если узел завис или упал

Переместить живую сессию X2Go на другой узел невозможно: программы пользователя работают
в памяти конкретного узла. Брокер делает то, что реально можно сделать:

* узел не отвечает `offline_after` опросов подряд (по умолчанию ~30 с) → помечается
  недоступным, новые входы туда не идут;
* пользователь, чья сессия была на этом узле, при входе сразу получает **новую сессию на
  свободном узле**; файлы на NFS целы, теряется только несохранённое в открытых программах;
* в панели такие сессии видны с пометкой «узел недоступен», их можно «Сбросить» из учёта;
* если узел жив, но сессия зависла, «Завершить» в панели вызывает штатную утилиту
  завершения X2Go. После успешного завершения пользователь может войти заново.
  При ошибке утилиты панель показывает отказ: автоматический SIGKILL от root по PID
  из БД отключён, поскольку устаревший PID может принадлежать другому процессу;
* для плановых работ — «Вывести на обслуживание»: новые сессии туда не идут, текущие
  доживают, после чего узел можно перезагружать. Флаг сохраняется между перезапусками.

После перезапуска самого брокера он знает о сессиях только тех узлов, что ответили;
сессии на узле, который недоступен с момента старта, в панели не видны.

## Отказоустойчивость брокера

Брокер почти не хранит состояния: конфигурация в файле, флаги обслуживания в
`state.json`. Второй экземпляр ставится так же, адрес `x2go.rrcki.ru` переносится между
ними через keepalived (VRRP). Флаги обслуживания на втором экземпляре нужно выставить
отдельно (или вынести `state_file` на общий том).

## Проверка

```bash
python3 tests/test_broker.py     # 57 сценариев на имитации фермы из шести узлов в трёх пулах
python3 -m unittest discover -s tests -p 'test_security.py' -v
```

Регрессионные тесты дополнительно проверяют обработку открытия LDAP-соединения,
ошибки каталога и агента, принадлежность клиентского события сессии и конкурентное
назначение мест. LDAP и узлы в этих проверках подменены; это не проверка совместимости
с настоящим AD, Astra или X2Go Client. CI запускает оба набора на Python 3.11 и 3.13.

Порядок развития до терминальной фермы и критерии допуска к пилоту:
[docs/PILOT.md](docs/PILOT.md).
