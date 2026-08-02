# Sentinel: Brainstorm / Discovery Notes

Date: 2026-08-01 · Goal: Design und Umsetzungsstrategie für Sentinel (Synthetic Monitoring Engine für Prometheus) durch relentless Interview schärfen und festhalten.

## Summary / key decisions
_(laufende Synthese, wird fortgeschrieben)_

### Umsetzungsstand (2026-08-01)
- **Doku-Nacharbeit erledigt:** README, architecture, metrics, configuration, Roadmap, CLAUDE.md an die 0.1-Entscheidungen angeglichen.
- **Code-Gerüst steht** (baut, `go vet` sauber, Tests grün mit `-race`): `go.mod` (`bodsch.me/sentinel`, go 1.26), `internal/probe` (Prober-Interface, Result, Timings, Diagnostics, FailureReason+Valid), `internal/clock` (Clock + Real + Fake), `internal/logging` (slog), `pkg/version` (ldflags), `cmd/sentinel/main.go` (Flags: --config/--validate/--version/--log-level/--log-format/--listen), `Makefile` (`make ci/build/test/release`). Tests: probe, clock, version.
- **`internal/config` implementiert** (baut, Tests grün mit `-race`): YAML-Load via `gopkg.in/yaml.v3` mit `KnownFields(true)` (unbekannte Felder abgelehnt), `Duration`-Wrapper, defaults→targets-Merge (triviale Regel), Validierung (Namen/Duplikate/Intervalle/URL-Schema+Host/Methode GET|HEAD/Regex-Compile/Status-Range/Label-Allow-List) mit gesammelten Fehlern via `errors.Join` und Target+Feld-Bezug. **`--validate` in main scharf** (Dry-Run: „config OK: N target(s)" exit 0 / gesammelte Fehler exit 1; Fail-fast beim Start). **`config.example.yaml`** erstellt und per Test (`example_test.go`) gegen den Validator verankert (Pflege-Regressionsschutz). Dep: `gopkg.in/yaml.v3` (direkt).
- **Adversarialer Review von `internal/config` (Agent) durchgeführt und Findings eingearbeitet:**
  - HIGH #1: Pointer-Aliasing bei geerbten HTTP-Defaults → `clonePtr`, jede Target-Instanz hat eigene Pointer (Test `TestDefaultsPointerNotAliased`).
  - #2: leere/kommentar-only Datei → jetzt „no targets defined" statt EOF (io.EOF als leere Config behandelt).
  - #3: leere Tag-Werte abgelehnt. #4: leere `body_regex`-Muster abgelehnt.
  - #5: explizites `interval/timeout: 0s` wird abgelehnt statt still gedefaultet → `Interval/Timeout` als `*Duration`, resolved-Getter (`ResolvedInterval/ResolvedTimeout`).
  - #6: configuration.md-Beispiele korrigiert (retries/validate_tls/http.timeout entfernt/verortet; „Complete Example" auf gültiges 0.1-YAML umgestellt, Verweis auf `config.example.yaml`).
  - #7 (LOW): URL mit eingebetteten Credentials (userinfo) abgelehnt (0.1 hat keine Auth, Secret-Hygiene).
  - **#8 (Interval-Untergrenze) bewusst NICHT umgesetzt** — „Interval-Governance" wurde in der Grill-Session (Vollständigkeits-Check) abgewählt. Falls später gewünscht: eigene Entscheidung.
- **`internal/store` implementiert** (baut, Tests grün mit `-race` inkl. Nebenläufigkeits-Test): threadsicherer `Store` (RWMutex), `Record{Target, Type, Labels, Result}` (nutzt `probe.Result`), `New/Set/Get/Remove/Snapshot/Len`. `name` = PK (leerer Name → panic, da Config-Validierung Eindeutigkeit+Nicht-Leere garantiert). Entfernen sofort, kein History. `Snapshot()` liefert frische Slice-Kopie; Label-Maps read-only-Kontrakt (Writer darf übergebene Map nach `Set` nicht mutieren) — beim Scheduler-Wiring beachten. Kein separater Agent-Review (kleiner RWMutex-Wrapper, -race grün); Aliasing-Kontrakt dokumentiert.
- **`internal/validator` implementiert** (Tests grün): `Validator`-Interface + `Status`/`BodyRegex`/`Header`; `Outcome{OK, Reason, Detail}` — Status→`http_status_error`, Body/Header→`validation_failed`. Header-Match ist **exakt** (dokumentiert; Substring wäre Folge-Feature). Reihenfolge Status→Body→Header.
- **`internal/probe/http` implementiert** (Tests grün mit `-race`, httptest + laufzeit-Certs): frische Verbindung pro Lauf (`DisableKeepAlives`, `ProxyFromEnvironment`, `InsecureSkipVerify` für manuelle TLS-Prüfung), httptrace-Phasen (finaler Hop), **manuelle Redirect-Schleife** (Follow bis max, Loop via normalisierter URL, HTTPS→HTTP-Downgrade, Limit; Chain = nur gefolgte Redirects), **manuelle TLS-Inspektion** (`inspectTLS`: expired/not-yet-valid/hostname → certificate_expired/invalid, remaining_days auch negativ), Total-Timeout via ctx, User-Agent, `max_body_bytes`-Cap, `classifyError` (dns/refused/timeout/tls + Fallback `network_error`). Entkoppelt von `config` via `http.Options` (Scheduler mappt später). Neu: `probe.Diagnostics`-Interface hat jetzt exportierte `ProbeType()`-Methode (vorher unexported Marker → Protokollpakete konnten es nicht implementieren); neuer Fehlergrund `probe.ReasonNetworkError` (+ metrics.md ergänzt).
- **Adversarialer Review von `internal/probe/http` (Agent) durchgeführt, alle 6 Findings eingearbeitet (je mit Test-Beleg):**
  - HIGH #1: `max_body_bytes` wurde durch `drain()` (`io.Copy(discard, body)`) ausgehebelt — voller Body vom Socket gelesen trotz Cap. Fix: nur `Close()` (keep-alives aus → kein Reuse-Drain nötig). Test `TestMaxBodyBytesBoundsSocketRead` (endloser Stream → schneller Erfolg statt Timeout).
  - HIGH #2: TLS nur auf finalem Hop inspiziert — abgelaufenes Cert auf Redirect-Zwischenhop blieb unentdeckt. Fix: TLS-Inspektion **pro Hop** (wie Downgrade-Check). Test `TestTLSExpiredOnRedirectHop`.
  - MED #3: Data-Race auf `hopTrace`-Feldern bei Dual-Stack (Happy Eyeballs, parallele ConnectStart/Done). Fix: Mutex + set/setIfZero, gelockte `timings()`.
  - MED #4: `RemainingDays` trunkierte Richtung Null → nicht negativ bei <24h abgelaufen. Fix: `math.Floor`. Test verschärft auf `< 0`.
  - LOW #5: schwache Loop-Normalisierung. Fix: Default-Ports (:80/:443) entfernt, leerer Pfad→„/". Test `TestNormalizeURL`.
  - LOW #6: totes Feld `hopTrace.start` entfernt.
  - Vom Agent als korrekt bestätigt: Body-Close auf allen Pfaden, classifyError-Reihenfolge (Deadline vor net.Timeout), TTFB-Baseline, Validator-Reihenfolge/Reason, leere PeerCertificates→tls_error, initiale URL in `visited`.
- **`internal/scheduler` implementiert** (Tests grün mit `-race`, 8×/20× stabil): Ticker-pro-Target (via `clock`) + globales Semaphore (`chan struct{}`, Default N=50), **skip-if-running** (`atomic.Bool` CAS, überlappender Tick → `skipped++`, nicht gequeued), deterministischer Jitter (FNV-Hash des Namens, kein rand), **graceful drain** (`Run` blockiert bis ctx-cancel, dann `wg.Wait`; in-flight-Ergebnisse nach cancel VERWORFEN via `ctx.Err()`-Check vor `store.Set`), Erfolge→debug/Fehler→info. Entkoppelt via `JobSpec{Name,Type,Interval,Labels,Prober}` (Scheduler kennt weder config noch http). `Stats()` liefert per-Target Skip-Counts für die Metrik-Schicht. Kernlogik white-box getestet (tick-skip, execute-store/discard, jitter, semaphore-bound), plus Fake-Clock-Integrationstest.
- **Adversarialer Review von `internal/scheduler` (Agent, inkl. 600× Shutdown-Stress unter `-race`) durchgeführt:**
  - **Bestätigt sauber (keine Defekte):** der `wg.Add`-nach-`Wait`-Shutdown-Pfad (tick-Add läuft immer bei Counter≥1 aus dem lebenden runJob → nie illegale 0→positiv-Transition), der Discard-Race (ctx intern synchronisiert, `ctx.Err()`-nil ⇒ Probe genuin fertig ⇒ harmlos), skip-if-running-Reset auf allen Pfaden, Semaphore kein Leak/Deadlock, Ticker-Lifecycle, `Stats()`.
  - **F1 (Low, real) eingearbeitet:** `Interval<=0` ließ `NewTicker(0)` paniken (real) / Fake-Clock-Deadlock. Fix: `Add` gibt jetzt Fehler zurück (leerer Name / Interval<=0 / nil Prober) → Misuse fällt beim Wiring auf statt die Goroutine zu killen.
  - **Härtungen eingearbeitet:** Panic-Recover im Probe-Goroutine (buggy Prober killt nicht den Scheduler); Initial-Verzögerung auf `maxInitialDelay`=10s gekappt (lange Intervalle → erste Probe trotzdem prompt); Semaphore-„unbounded wait"-Verhalten bewusst dokumentiert (eventual coverage > drop; skip-if-running deckt Overlaps).
  - **Test-Lücken geschlossen:** `Add`-Validierung, Discard-**während**-Probe (statt pre-cancelled), Panic-Recover.
- **`internal/metrics` implementiert** (Tests via `Gather`): dedizierte Registry + `build_info`; generischer `ProbeCollector` (success/duration/last_success/failure_info(vanishing)/skipped) liest `store.Snapshot()`+`scheduler.Stats()` beim Scrape; fester Label-Satz (leere Werte für fehlende Tags → dimensional konsistent). HTTP-Collector (`http.Collector`: Phasen-Timings/status/redirects/tls-cert) lebt im `http`-Paket (self-registering, Q3). Store erweitert: `LastSuccess` carry-forward; `TLSInfo.Valid`.
- **`internal/server` implementiert** (Tests): `/metrics` (promhttp), `/healthz` (liveness immer 200), `/readyz` (readiness = Sentinel-Selbstzustand via `SetReady`), Port :8080, `Start`/`Shutdown` graceful.
- **Runtime in `main` verdrahtet** (`serve`): config→`http.Options`→`scheduler.Add`, Collectors registriert, Server gestartet, `signal.NotifyContext` (SIGINT/SIGTERM) → Scheduler-Drain (bounded `shutdownTimeout`=10s, in-flight verworfen) → Server-Shutdown → exit 0. Readyz erst nach Scheduler-Start true.
- **Logging verfeinert:** statuswechsel-basiert (Transitions „probe failing"/„probe recovered" auf info, Steady-State auf debug) — kein Log-Spam bei dauerhaft down (im E2E entdeckt+behoben).
- **✅ E2E verifiziert:** Binary gegen lokale Ziele (eigener `/healthz` = success, `/does-not-exist` = http_status_error) laufen lassen; `/metrics` gescrapt: `probe_success` 1/0, `failure_info{reason}` nur beim Fehler (vanishing), `http_status_code`/`ttfb`/`last_success`/`build_info` korrekt, Label-Satz konsistent; `/readyz`→200, `/healthz`→ok; SIGTERM → graceful shutdown („sentinel stopped", exit 0).

## 🎯 Version 0.1 ist feature-complete und lauffähig.
Alle Bausteine implementiert, getestet (`-race`), adversarial reviewed (config/http/scheduler) und end-to-end verifiziert. Benchmarks + Skalierungsprofil ergänzt (1000 Targets: ~1004 Goroutines, ~4.3 MiB Heap, ~10 ms Scrape). 0.1 committet + nach origin/main gepusht.

## 0.2 — in Arbeit (Branch `feature/0.2-dns-probe`)
- **DNS-Probe** (Entscheidung: `miekg/dns`, Record-Typen A/AAAA/MX/TXT):
  - Config: `Target.DNS{Server,Query,Type,Expected}`, Validierung generalisiert auf „genau ein Protokoll" (http xor dns), DNS-Validierung (Server host[:port], Query, Type). Type-Default A, uppercase.
  - `internal/probe/dns`: Query via miekg, Total-Timeout via ctx, RCODE/Answer-Count/Answers in `Diagnostics`, Reason-Mapping (timeout / dns_error bei RCODE≠NOERROR / validation_failed bei Expected-Mismatch). Ohne `expected`: NOERROR=Erfolg auch bei 0 Answers (answer_count ist Alert-Signal).
  - `dns.Collector`: query_duration/response_code/answer_count, self-registering (metrics-Paket unverändert → Q3-Erweiterbarkeit bestätigt).
  - main: Protokoll-Dispatch (`buildProber`). Tests via lokalem `dns.Server` (hermetisch).
  - **E2E verifiziert:** gemischte HTTP+DNS-Config; A/MX = success, NXDOMAIN → success=0 + response_code=3 + failure_info{dns_error}; graceful shutdown.
  - **Adversarialer Review läuft** — Findings danach eingearbeitet.
  - Doku-Nacharbeit (DNS von „0.2 geplant" auf „implementiert") noch offen.

### Verdichteter 0.1-Scope (das „Was")
Schmaler vertikaler HTTP-Durchstich, produktionsreif:
- **Nur HTTP/HTTPS-Probe**, aber vollständiges Runtime-Gerüst (Config → Scheduler → Probe → Store → metrics/server).
- **Probe:** frische Verbindung pro Lauf, `httptrace`-Phasen (DNS/TCP/TLS/TTFB/Download), GET+HEAD, eigener User-Agent, `max_body_bytes` 1 MB, ein Total-Timeout.
- **Validatoren:** Status, Body-Regex, Header (via `Validator`-Interface).
- **Redirects:** Follow bis max, Loop- + HTTPS→HTTP-Downgrade-Erkennung; Phasen-Timings = finaler Hop, Gesamtdauer = alle Hops.
- **TLS:** manuelle Cert-Inspektion (Ablauf, Hostname, remaining_days).
- **Scheduler:** Ticker-pro-Target + Semaphore, Skip-if-running, Skip-Counter; Clock-Interface.
- **Store:** threadsicher, `name` = PK, entfernte Targets sofort raus.
- **Metriken:** self-registrierende Collectors, `probe_success` primär, `probe_failure_info{reason}` (verschwindet bei Erfolg), fester Label-Satz, `build_info`. **Keine Histogramme in 0.1.**
- **Server:** `/metrics` + `/healthz` + `/readyz` auf `:8080`, Readiness = Sentinel-Selbstzustand.
- **Config:** `defaults` + `targets` (keine Templates), ein File via `--config`, `--validate`-Dry-Run, Fail-fast; Erreichbarkeit nie Teil der Validierung.
- **Logging:** slog JSON, Erfolge=debug/Fehler=info, festes Feld-Schema.
- **Betrieb:** graceful shutdown (drain, Default 10s, In-Flight verworfen), `--version`, Forgejo-CI + Makefile-Logik, `CGO_ENABLED=0` statisch (linux+darwin, amd64+arm64).
- **Kein Retry** in der Probe (Dämpfung via Prometheus `for:`), **kein Hot-Reload**, **kein Auth/Body/Custom-Header/Proxy-Config** (aber `HTTP_PROXY`-Env respektiert).

### Bewusst nach 0.2+ verschoben
DNS/TCP/ICMP/TLS-standalone-Probes · Histogramme · Templates · Hot-Reload · JSONPath/XPath · Retry · Auth+Secret-Handling · Custom-Request-Header/Body · POST/PUT · per-Target-Proxy · feingranulare Phasen-Timeouts · freie Tags-als-Labels (mit Governance) · Domain-Change-Redirect-Policy · Chain/OCSP/SAN-TLS · Debug-API · connection reuse (optional).

### Doku-Nacharbeit (aus Entscheidungen abgeleitet)
- README/architecture: connection pooling ist NICHT-Ziel für Monitoring-Probes (Q10).
- architecture.md: `ProbeResult{map[string]float64}` → typisiertes Result (Q2).
- metrics.md: `probe_failure_reason` → `probe_failure_info` mit Verschwind-Semantik (Q18); Histogramme als 0.2 (Q4); `probe_skipped_total` ergänzen (Q8).
- configuration.md: Templates/Retry/Proxy/multi-level-Timeouts als 0.2; „beliebige Tags → Labels" auf festen Satz einschränken (Q14/Q19/Q20/Q24/Q27).
- Roadmap.md: 0.1 auf HTTP-only reduzieren, Nicht-HTTP-Protokolle nach 0.2 (Q1).
- **ERLEDIGT:** CLAUDE.md Beispielstruktur (Q22) + Einleitung/Features (Q23) bereits in dieser Session aktualisiert.

### Entscheidungsprotokoll
- Ausgangslage: 5 Design-Dokumente vorhanden (README, architecture, configuration, metrics, Roadmap). Noch kein Code (`internal/`, `pkg/` existieren nicht). Reine Design-Phase.
- **Entscheidung (Q1):** Version 0.1 = schmaler vertikaler HTTP-Durchstich. Nur HTTP/HTTPS, aber vollständiges Gerüst (Config → Scheduler → Worker-Pool → Probe → Result-Store → `/metrics`) inkl. HTTP-Timing-Phasen. DNS/TCP/ICMP/TLS-standalone kommen als 0.2, sobald das Probe-Interface steht.
- **Entscheidung (Q2):** Typisiertes `Result` (kein `map[string]float64`). `FailureReason` als stabiles Enum. Timings als typisierte Phasen-Struktur. ABER: Diagnostics muss um neue Protokolle erweiterbar sein, OHNE den Exporter anzufassen (kein Type-Switch pro Protokoll im Exporter).
- **Entscheidung (Q3):** Erweiterbarkeit via **self-registrierende Collectors**. Jedes Protokoll-Paket registriert seinen eigenen `prometheus.Collector` an einer Registry. Kopplung an `client_golang` wird bewusst akzeptiert (Idiomatik > Entkopplung). Exporter = `promhttp.Handler` über die Registry; kennt keine Protokolldetails.
- **Entscheidung (Q4):** **Hybrides Metrik-Modell.** (1) Zustands-Metriken (success, aktueller TTFB-Gauge, cert-remaining-days, failure_reason) → Custom `Collector.Collect()` liest beim Scrape live aus dem Result-Store (immer aktuell, kein Stale, keine Historie im Prozess). (2) Verteilungs-Metriken (Histogramme) → klassische `prometheus.Histogram`-Objekte, von der Probe zum Laufzeitpunkt via `.Observe()` befüllt. **Histogramme erst in 0.2**; 0.1 nur Zustands-Gauges.
- **Entscheidung (Q5):** Result-Store: **`name` ist harter Primärschlüssel**, Eindeutigkeit bei Config-Load erzwungen (Duplikat = Config-Fehler). Bei Target-Entfernung (später via Reload): **sofort aus dem Store raus**, kein Tombstone/Grace in 0.1. Metrik verschwindet dann aus `/metrics`; Prometheus-Staleness ist akzeptiert.
- **Entscheidung (Q6):** **Kein Hot-Reload in 0.1.** Config wird einmal beim Start geladen + validiert. Reload = Prozess-Neustart (systemd/K8s). Auch kein SIGHUP-Full-Reload in 0.1. Hot-Reload mit Diff = bewusstes späteres Feature (0.2/0.4).
- **Entscheidung (Q7):** Skalierungsziel = **Hunderte Targets**. Scheduling = **Hybrid**: Ticker-pro-Target meldet Fälligkeit (Goroutine je Target, bei Hunderten unkritisch), aber Ausführung geht durch ein **Semaphore-begrenztes Worker-Gate** (`chan struct{}`, Kapazität N) → harte Obergrenze gleichzeitiger Probes. Kein voller zentraler Queue-/Scheduler-Apparat in 0.1. Trennung „Fälligkeit vs. Ausführung" von Anfang an vorhanden.
- **Entscheidung (Q8):** Überlast-Verhalten: (a) **Skip-if-running pro Target** — höchstens ein laufender Probe je Target (atomic-Flag/TryLock); überlappender Tick wird verworfen (kein Selbst-Stau). (b) **Am globalen Semaphore kurz warten** statt sofort verwerfen; überschreitet die Wartezeit den nächsten Tick, greift wieder (a). (c) Jeder verworfene/geskippte Lauf wird gezählt: `sentinel_probe_skipped_total` (Überlast sichtbar machen).
- **Entscheidung (Q9):** Modulpfad = **`bodsch.me/sentinel`**. Binary/Command unter **`cmd/sentinel/main.go`**. Metrik-Präfix bleibt `sentinel_`. Projektname Sentinel wird beibehalten (Generik/Namenskollision bewusst in Kauf genommen für privates On-Prem-Tool).
- **Entscheidung (Q10):** **Immer frische Verbindung pro Probe** (`DisableKeepAlives: true` / kurzlebiger Transport). Damit werden ALLE Phasen-Timings (DNS/TCP/TLS/TTFB/Download) bei jedem Lauf vollständig und vergleichbar gemessen. Timing via `net/http/httptrace.ClientTrace`. **Connection-Reuse/Pooling aus den Docs ist ein Nicht-Ziel für Monitoring-Probes** (widerspricht dem Messzweck: reused connections liefern keine DNS/TCP/TLS-Phase). Reuse ggf. später optional pro Target (0.2+).
- **Entscheidung (Q11):** TLS-Diagnose via **manuelle Cert-Inspektion** — Handshake mit `InsecureSkipVerify: true` (schaltet nur Gos Auto-Fail ab, NICHT TLS!), dann eigene Verifikation. So ist die Cert-Kette immer greifbar und `certificate_expired` klar von „unreachable" unterscheidbar; `remaining_days` auch bei abgelaufenem Cert berechenbar. **0.1-Umfang: Ablauf + Hostname-Match + remaining_days.** Volle Chain-Verifikation/OCSP/SAN-Detail = 0.2. `sentinel_tls_certificate_valid` ergibt sich aus der manuellen Prüfung.
- **Entscheidung (Q12):** Logging = **`log/slog`** (Stdlib, kein externer Dep). **JSON-Handler als Default**, Text-Handler optional für lokale Dev (per Flag/Env). Einheitliches Schema via pro-Probe abgeleitetem Logger (`With("target", ..., "probe_type", ...)`): Kernfelder target, probe_type, success, duration_ms, failure_reason, phase. Zentrales `internal/logging`-Paket kapselt Handler + Feldkonventionen; kein direktes `slog.Default()` im Fachcode. **Erfolge auf `debug`, Fehler/Statuswechsel auf `info`** (Zustand lebt in Metriken, Log dient Diagnose). Level konfigurierbar, Default `info`.
- **Entscheidung (Q13):** Versionierung = **eine Binary-Version** in `pkg/version` (`Version`, `Commit`, `BuildDate`), via `-ldflags` beim Build injiziert. Überall sichtbar: `sentinel --version`, Metrik `sentinel_build_info{version,commit,...}` (Wert 1), und Log-Startzeile. „Alle Komponenten erhalten eine Versionsnummer" (CLAUDE.md) = Versionsinfo überall abrufbar, NICHT pro-Probe separat versioniert. Keine Plugin-/Pro-Komponente-Versionierung in 0.1.
- **Entscheidung (Q14):** Config-Layering in 0.1 = **nur `defaults` + `targets`, keine Templates.** Merge-Regel trivial: Target-Wert gewinnt, sonst Default. Kein Deep-Merge. Templates (mit klarer Merge-Semantik) = 0.2. Verschachtelte Merge-Komplexität (Header-Maps, Regex-Listen) bewusst vermieden.
- **Entscheidung (Q15):** HTTP-Validatoren 0.1 = **Status-Code + Body-Regex + Header-Match** (JSONPath/XPath → 0.2). **`Validator`-Interface ab 0.1** (die drei sind erste Implementierungen; 0.2 hängt neue ein). Body-Lesen gedeckelt durch **`max_body_bytes`, Default 1 MB** — Body bis Limit lesen dann abschneiden, Download-Dauer/-Größe weiter messbar. Gilt zugleich als DoS-Härtung (bösartiges Target kann Sentinel nicht per Endlos-Body aushungern).
- **Entscheidung (Q16):** Redirect-Handling 0.1: Follow bis `max_redirects` (Default 10), **Loop-Detection** via Set normalisierter URLs, `redirect_limit_exceeded` als eigener failure_reason, **HTTPS→HTTP-Downgrade-Erkennung** (billig + sicherheitsrelevant). „Unexpected domain change" → 0.2 (braucht Allow-Policy). **Timing-Zuordnung:** Phasen-Timings (DNS/TCP/TLS/TTFB/Download) beziehen sich auf den **finalen Hop** (dessen Antwort validiert wird); `sentinel_http_duration_seconds` = **Gesamtzeit über alle Hops** (inkl. Redirect-Overhead). Eigener Redirect-Handler nötig (Gos CheckRedirect), da fresh-connection pro Hop + Kettenprotokollierung.
- **Entscheidung (Q17):** HTTP-Server-Oberfläche: **`/metrics` + `/healthz` (Liveness) + `/readyz` (Readiness)**, alles auf **einem Port `:8080`** (Default konfigurierbar). Keine Auth auf `/metrics` in 0.1 (trusted network / Reverse-Proxy; nur dokumentieren). **Readiness = Sentinel-Selbstzustand** (Config geladen + Scheduler gestartet), NICHT Target-Zustand — fehlschlagende Probes machen Sentinel NICHT unready (sonst würde K8s es genau bei Ausfällen neustarten). Liveness = 200 solange Prozess läuft.
- **Entscheidung (Q18):** `FailureReason` = eigener Go-Typ (`FailureReason string`) mit definierten Konstanten + `Valid()`, keine freien Strings. **0.1-Satz:** dns_error, tcp_timeout, connection_refused, tls_error, certificate_expired, certificate_invalid (Hostname-Mismatch), redirect_loop, redirect_limit_exceeded, downgrade, http_status_error, validation_failed, timeout. **Metrik-Repräsentation:** `sentinel_probe_success` (0/1) bleibt primäre Alert-Metrik. Reason als **Info-Serie** `sentinel_probe_failure_info{reason="..."} 1`, die **nur bei Fehler existiert und bei Erfolg gar nicht emittiert wird** (Collector-liest-Store macht das trivial → keine verwaisten Zeitreihen, immer nur EINE Reason-Serie pro Target). Vermeidet das „enum-value-as-label"-Anti-Pattern aus metrics.md.
- **Entscheidung (Q19):** Labels = **fester, definierter Satz in 0.1**: `target`, `type`, `environment`, `location`, `service`. `tags:` in der Config, die NICHT in dieser Liste stehen, werden bei der **Config-Validierung abgelehnt** (explizit, nicht still ignoriert). Schützt vor versehentlicher Cardinality-Explosion. Freie Tags-als-Labels MIT Governance (Sanitizing, Allow-List, Warn-Schwelle) = bewusstes 0.2-Feature. `target` als hochkardinal-begrenzt (Anzahl Targets) ist gewollt.
- **Entscheidung (Q20):** **Kein In-Probe-Retry in 0.1.** Ein Probe-Lauf = ein Versuch. Alert-Dämpfung transienter Fehler gehört zu Prometheus (`for:` in der Alert-Rule), nicht in den Exporter. Hält Probe-Logik sauber, vermeidet Mehrdeutigkeit (welcher Versuch prägt TTFB/success). `retry`-Block aus configuration.md → 0.2 (falls flakige interne Netze es erfordern), dann mit Metriken=letzter Versuch, Gesamt-Timeout über alle Versuche, `sentinel_probe_retries_total`.
- **Entscheidung (Q21):** **Hermetische Teststrategie.** HTTP-Probe gegen `httptest.Server` (Status/Header/langsame Antworten/Redirect-Ketten+Loops). TLS-Tests via `httptest.NewTLSServer` + **zur Laufzeit generierte Zertifikate** (gültig/abgelaufen/falscher-Hostname) statt eingecheckter Cert-Dateien → „stabile Testdaten" = reproduzierbar erzeugt, nicht eingefroren (kein Selbst-Ablauf-Bruch). Fehlerfälle gezielt: connection_refused, timeout, Body > max_body_bytes. Table-driven, **`-race` in CI verpflichtend** (Store/Collector-Nebenläufigkeit). **Zeit hinter Clock-Interface** (kein direktes `time.Now()`/`time.Ticker` im Scheduler) → deterministische Scheduler-/Jitter-/Skip-Tests. Scheduler/Store per Fake-`Prober` isoliert testbar.
- **Entscheidung (Q22):** Konkrete Paketstruktur 0.1 (siehe Block unten). Abweichungen von CLAUDE.md-Beispiel bewusst: **`internal/discovery` entfällt** (Sentinel entdeckt nichts, es probet konfigurierte Targets — Name stammt aus überholter „Autodiscovery"-Idee). **`monitoring` aufgeteilt** in `probe`/`scheduler`/`store` (Separation of Concerns). `exporter` → `metrics` + `server`. Neu: `validator`, `clock`. **CLAUDE.md Beispielstruktur wird entsprechend aktualisiert** (vom User beauftragt).

```text
cmd/sentinel/main.go       # Flags, Config, Server+Scheduler starten, graceful shutdown
internal/
  config/                  # YAML laden/validieren, defaults mergen (Q14), Label-Allow-List (Q19)
  probe/                   # Prober-Interface, Result, FailureReason-Enum (Q2, Q18)
    http/                  # HTTP-Probe: httptrace-Timings, Redirects (Q10, Q16), TLS-Inspektion (Q11)
  validator/               # Validator-Interface + status/regex/header (Q15)
  scheduler/               # Ticker-pro-Target + Semaphore + Skip-if-running (Q7, Q8), Clock (Q21)
  store/                   # Result-Store, threadsicher, name=PK (Q5)
  metrics/                 # self-registrierende Collectors, Registry, build_info (Q3, Q4, Q18)
  server/                  # /metrics, /healthz, /readyz (Q17)
  logging/                 # slog-Setup, Feldkonventionen (Q12)
  clock/                   # Clock-Interface + Real/Fake (Q21)
pkg/version/               # Version/Commit/BuildDate (Q13)
```

## Q&A log

### Q1 — Scope von Version 0.1
- **Asked:** Soll 0.1 der schmale HTTP-Durchstich sein oder mehrere Protokolle gleichzeitig?
- **Captured:** Schmaler HTTP-Durchstich für 0.1. Bewusste Verkleinerung gegenüber der Roadmap (die 0.1 mit HTTP+DNS+TCP+ICMP+TLS überlädt). Roadmap muss entsprechend angepasst werden: die dort unter 0.1 gelisteten Nicht-HTTP-Protokolle wandern nach 0.2.
- **Flags:** Roadmap.md ist noch nicht an diese Scope-Entscheidung angepasst -> Bodo (bei Umsetzung).

### Q2 — Das Probe-Interface / Ergebnis-Modell
- **Asked:** Typisierte Result-Struktur vs. generisches `map[string]float64` aus architecture.md?
- **Captured:** Typisierter Ansatz gewählt. Result mit `Success`, `FailureReason` (Enum), typisierten `Timings`, `Timestamp`. Zusätzliche Anforderung: **Diagnostics-Erweiterbarkeit ohne Exporter-Änderung** — ein neues Protokoll darf keinen neuen Type-Switch-Zweig im Exporter erzwingen. => architecture.md (`ProbeResult` mit `map[string]float64`) ist damit überholt und muss angepasst werden.
- **Flags:** architecture.md `ProbeResult`-Definition veraltet -> bei Umsetzung anpassen. Konkreter Mechanismus für exporterfreie Erweiterbarkeit -> in Q3 zu klären.

### Q3 — Erweiterbarkeitsmechanismus für Metriken
- **Asked:** Selbstbeschreibende `Sample`-Liste (entkoppelt) vs. self-registrierende Collectors (idiomatisch, gekoppelt an client_golang)?
- **Captured:** **Self-registrierende Collectors.** Idiomatik ist wichtiger als Entkopplung von der Prometheus-Client-Lib. Jedes Protokoll bringt seinen eigenen Collector mit, registriert ihn an einer (custom) `prometheus.Registry`. Der Exporter serviert nur `promhttp.Handler`.
- **Konsequenz:** Protokoll-Pakete dürfen `client_golang` importieren. Es braucht eine zentrale Registry-Instanz (nicht die globale Default-Registry, um Tests isolierbar zu halten).
- **Flags:** Gauge-Metriken (Zustand) vs. Histogramme (Observations) haben unterschiedliche Lebenszyklen im entkoppelten Scrape-Modell -> in Q4 zu klären.

### Q4 — Gauges vs. Histogramme im entkoppelten Scrape-Modell
- **Asked:** Hybrid (Zustand via Collector-liest-Store, Verteilung via observierte Histogramme) festschreiben? Histogramme in 0.1 oder 0.2?
- **Captured:** Hybrid bestätigt. **Histogramme erst in 0.2.** In 0.1 werden nur Zustands-Gauges über einen Collector exportiert, der beim Scrape live aus dem Result-Store liest. Kein Histogramm-Code in 0.1.
- **Konsequenz für Result-Store:** muss threadsicher gleichzeitig beschreibbar (Probe-Worker) und lesbar (Collector beim Scrape) sein — RWMutex o.ä.
- **Flags:** metrics.md listet Histogramme prominent; muss klarstellen, dass diese 0.2 sind.

### Q5 — Result-Store: Schlüssel & Lebenszyklus
- **Asked:** `name` als harter Primärschlüssel? Entfernte Targets sofort raus oder Tombstone?
- **Captured:** `name` = harter PK, Eindeutigkeit bei Config-Load erzwungen. Entfernte Targets: **sofort aus dem Store**, kein Tombstone. Store muss threadsicher sein (Worker schreiben, Collector liest beim Scrape).
- **Flags:** —

### Q6 — Hot-Reload in 0.1?
- **Asked:** Hot-Reload komplett aus 0.1, oder wenigstens SIGHUP-Full-Reload?
- **Captured:** Komplett raus. 0.1 lädt Config nur beim Start. Reload = Prozess-Neustart. Kein SIGHUP in 0.1. => vereinfacht Scheduler massiv (statische Target-Menge über Prozesslaufzeit).
- **Flags:** configuration.md/architecture.md beschreiben Hot-Reload ausführlich -> als „Future" kennzeichnen.

### Q7 — Scheduling-Modell & Skalierung
- **Asked:** Ticker-pro-Target vs. zentraler Scheduler+Queue? Erwartete Target-Zahl?
- **Captured:** Zielgröße **Hunderte** Targets. Hybrid gewählt: Ticker-pro-Target für Fälligkeit + Semaphore (`chan struct{}`) für bounded concurrency bei der Ausführung. Jitter via initialem Offset pro Ticker. Voller zentraler Scheduler (Timing-Wheel/Heap, Queue, Backpressure) = spätere Skalierungsstufe, nicht 0.1.
- **Offene Detailfrage:** Verhalten wenn Semaphore voll ist und ein Target fällig wird (Skip vs. Warten) -> Q8.
- **Flags:** —

### Q8 — Überlast: überlappende & gestaute Probes
- **Asked:** Skip-if-running + am Semaphore warten + Skip-Counter?
- **Captured:** Bestätigt. Skip-if-running pro Target (max. 1 laufender Probe), am globalen Semaphore kurz warten, jeder Skip als `sentinel_probe_skipped_total` gezählt. Neue Metrik, in metrics.md nicht enthalten -> ergänzen.
- **Flags:** `sentinel_probe_skipped_total` fehlt in metrics.md -> ergänzen.

### Q9 — Modulpfad & Binary-Name
- **Asked:** `bodsch.me/sentinel` als Modulpfad, `cmd/sentinel/`?
- **Captured:** Bestätigt. Modul `bodsch.me/sentinel`, Command `cmd/sentinel/main.go`, Metrik-Präfix `sentinel_`. Name Sentinel bleibt.
- **Flags:** —

### Q10 — Connection-Reuse vs. Phasen-Timings
- **Asked:** Immer frische Verbindung (A) vs. Reuse mit Flag (B) vs. konfigurierbar (C)?
- **Captured:** **A** für 0.1 — immer frische Verbindung, keine Keep-Alives, `httptrace` für vollständige Phasen. Wichtige Design-Klarstellung: „connection reuse" aus README/architecture ist für Monitoring-Probes ein NICHT-Ziel (widerspricht dem Sinn der Phasenmessung). Dokumente müssen das korrigieren.
- **Flags:** README.md/architecture.md preisen connection pooling als Vorteil -> umformulieren: gilt nicht für Monitoring-Probes in 0.1.

### Q11 — TLS-Validierung & Fehler-Differenzierung
- **Asked:** Manuelle Cert-Inspektion via InsecureSkipVerify? Trias Ablauf/Hostname/remaining_days für 0.1 ausreichend?
- **Captured:** Manuelle Inspektion bestätigt. 0.1: Ablauf + Hostname-Match + remaining_days. Chain/OCSP/SAN -> 0.2. `InsecureSkipVerify: true` hier bewusst als Diagnose-Mittel, nicht als Sicherheitslücke (eigene Verifikation ersetzt Gos Auto-Check).
- **Flags:** Sicherheits-Hinweis dokumentieren, warum `InsecureSkipVerify` hier korrekt ist (sonst Code-Review-Stolperstein).

### Q12 — Logging
- **Asked:** slog + festes Schema + Erfolge auf debug? JSON oder Text default?
- **Captured:** `log/slog`, JSON default (Text optional dev), Erfolge auf debug / Fehler auf info. Zentrales `internal/logging`-Paket, pro-Probe abgeleiteter Logger mit festen Kernfeldern.
- **Flags:** —

### Q13 — Versionierung
- **Asked:** Eine Binary-Version überall sichtbar (Lesart 1) oder pro-Komponente versioniert (Lesart 2)?
- **Captured:** Lesart 1. Eine Binary-Version aus `pkg/version` via ldflags; sichtbar über `--version`, `sentinel_build_info`-Metrik, Log-Startzeile. Keine Pro-Probe-Versionierung.
- **Flags:** —

### Q14 — Config-Layering
- **Asked:** Templates in 0.1 oder nur defaults+targets?
- **Captured:** Nur `defaults` + `targets` in 0.1. Keine Templates (→ 0.2). Triviale Merge-Regel (Target > Default), kein Deep-Merge.
- **Flags:** configuration.md zeigt Templates prominent -> als 0.2 kennzeichnen.

### Q15 — HTTP-Validatoren & Body-Limit
- **Asked:** Welche Validatoren in 0.1? Interface? max_body_bytes-Default?
- **Captured:** Status + Body-Regex + Header in 0.1, `Validator`-Interface ab Start, `max_body_bytes` Default **1 MB**. JSONPath/XPath → 0.2.
- **Flags:** —

### Q16 — Redirect-Handling & Timing-Zuordnung
- **Asked:** Umfang 0.1 (Follow/Loop/Limit/Downgrade/Domain-Change)? Timings finaler Hop vs. Summe?
- **Captured:** Follow + Loop + Limit + HTTPS-Downgrade in 0.1; Domain-Change → 0.2. Phasen-Timings = finaler Hop; Gesamtdauer = alle Hops. Eigener CheckRedirect-Handler.
- **Flags:** —

### Q17 — HTTP-Server-Oberfläche
- **Asked:** Endpoints/Port/Auth/Readiness-Semantik? Wunsch-Port?
- **Captured:** `/metrics` + `/healthz` + `/readyz` auf Port **8080** (konfigurierbar), keine Auth in 0.1. Readiness = Sentinel-Zustand, nicht Target-Zustand.
- **Flags:** —

### Q18 — failure_reason Enum & Metrik-Repräsentation
- **Asked:** Erweiterter Enum-Satz? Reason als bei-Erfolg-verschwindende Info-Serie?
- **Captured:** Beides bestätigt. Typisiertes `FailureReason`-Enum (0.1-Satz s. Summary). `sentinel_probe_success` primär; Reason als `sentinel_probe_failure_info{reason}` nur bei Fehler. Kein enum-as-label-Anti-Pattern.
- **Flags:** metrics.md `sentinel_probe_failure_reason`-Beispiel überarbeiten (Anti-Pattern) -> in `_failure_info` mit Verschwind-Semantik ändern.

### Q19 — Label-Strategie & Cardinality
- **Asked:** Fester Label-Satz (A) vs. freie Tags-als-Labels mit Governance (B)?
- **Captured:** A für 0.1. Feste Liste (target, type, environment, location, service); unbekannte Tags werden bei Validierung abgelehnt. Freie Tags → 0.2 mit Governance.
- **Flags:** configuration.md „These values become Prometheus labels" (beliebige Tags) -> auf festen Satz einschränken/klarstellen.

### Q20 — Retries
- **Asked:** In-Probe-Retry in 0.1 oder Dämpfung via Prometheus `for:`?
- **Captured:** Kein In-Probe-Retry in 0.1. Ein Lauf = ein Versuch. Dämpfung via Prometheus Alert `for:`. Retry-Block → 0.2.
- **Flags:** configuration.md Retry-Sektion als 0.2 kennzeichnen.

### Q21 — Teststrategie
- **Asked:** Hermetische Tests (httptest + laufzeit-Certs + -race)? Clock-Interface oder reale Intervalle?
- **Captured:** Hermetisch bestätigt; zusätzlich **Clock-Interface** für deterministische Scheduler-Tests (kein direktes time.Now/Ticker). Laufzeit-generierte Certs, `-race` verpflichtend, Fake-Prober für Scheduler/Store.
- **Flags:** —

### Q22 — Paketstruktur
- **Asked:** Konkrete Struktur ok? Abweichung von CLAUDE.md (discovery raus, monitoring aufteilen)?
- **Captured:** Struktur bestätigt. discovery raus, monitoring → probe/scheduler/store, exporter → metrics+server, neu validator+clock. **CLAUDE.md „Beispielstruktur" wurde in dieser Session bereits aktualisiert** (CLAUDE.md:141–157).
- **Flags:** —

### Q23 — Projektidentität (CLAUDE.md-Einleitung)
- **Asked:** Autodiscovery ganz raus oder als späteres Feature parken? Einleitung jetzt umschreiben?
- **Captured:** **Autodiscovery komplett entfernt** (überholte Ur-Idee, widerspricht synthetic monitoring). CLAUDE.md-Einleitung + Feature-Liste in dieser Session neu geschrieben (aktives Verproben konfigurierter Targets, phasengenaue Diagnostik). Kein Netzwerk-Scan als Roadmap-Punkt.
- **Flags:** —

### Q24 — Timeout-Modell
- **Asked:** Mehrstufige Timeouts (total/dns/connect/tls) oder nur total in 0.1? Sekundäre TLS/Dial-Schwelle als Detail ok?
- **Captured:** **Nur ein `timeout` (total) pro Target in 0.1**, via `context.WithTimeout` über gesamten Lauf inkl. aller Redirect-Hops. Bei Total-Timeout: `failure_reason=timeout` + `phase`-Feld (aus httptrace) zeigt grob wo es hing. Feingranulare Phasen-Timeouts → 0.2. Interne sekundäre TLS/Dial-Schutzschwelle (nicht konfigurierbar) erlaubt, damit ein TLS-Hänger nicht das Total auffrisst.
- **Flags:** configuration.md „Timeouts" (total/dns/connect/tls) als 0.2 kennzeichnen.

### Q25 — Graceful Shutdown
- **Asked:** Shutdown-Sequenz? In-Flight verwerfen? shutdown_timeout-Default?
- **Captured:** Sequenz: SIGTERM/SIGINT → root-Context cancel → Scheduler stopp (keine neuen Probes) → **Drain mit `shutdown_timeout` (Default 10s)** → laufende Probes laufen aus oder werden nach Frist hart abgebrochen → HTTP-Server `Shutdown(ctx)` mit selber Frist → exit 0. **Abgebrochene In-Flight-Probes werden verworfen** (NICHT als `probe_success=0` gewertet, nicht in Store geschrieben) — kein irreführender Failure beim geordneten Herunterfahren.
- **Flags:** —

### Q26 — CI & Build-Targets
- **Asked:** Welches CI führend? Makefile-Logik? CGO_ENABLED=0 statisch?
- **Captured:** **Forgejo primär** (self-hosted, On-Prem), GitHub optional/Mirror. **Logik im Makefile** (`make ci` = fmt vet lint test-race build); beide CI-Configs = dünne Wrapper, keine Logik in YAML. golangci-lint. Cross-Build für linux/{amd64,arm64} + darwin/{amd64,arm64}, **`CGO_ENABLED=0` statisch**. macOS wird gebaut, nicht zwingend in CI getestet. Implikation: Go-interner DNS-Resolver erzwingen (`GODEBUG=netdns=go`) für OS-übergreifend gleiches Verhalten.
- **Flags:** —

### Q27 — HTTP-Request-Oberfläche 0.1
- **Asked:** Was darf die Probe in 0.1 senden? HTTP_PROXY respektieren oder ignorieren?
- **Captured:** 0.1 Sende-Seite klein: **Methoden GET + HEAD** (HEAD gratis für Verfügbarkeit/TLS ohne Body). Eigener **User-Agent `sentinel/<version>`**. KEINE Custom-Request-Header, KEINE Auth, KEIN Request-Body in 0.1 (alles → 0.2; Auth zusammen mit Secret-Handling via Env-/Datei-Referenzen einmal richtig in 0.2). Per-Target-Proxy-Config → 0.2, aber **`HTTP_PROXY`/`HTTPS_PROXY`-Env wird in 0.1 respektiert** (`http.ProxyFromEnvironment`, in Firmennetzen nötig, quasi kostenlos).
- **Flags:** configuration.md Proxy-Sektion (per-target) als 0.2 kennzeichnen; Auth/Secret-Handling als 0.2-Thema notieren.

### Q28 — Config-Laden, CLI & Validierungs-Modus
- **Asked:** Ein File via --config? --validate Dry-Run? Fail-fast? Erreichbarkeit Teil der Validierung?
- **Captured:** **Ein Config-File** via `--config` (Env `SENTINEL_CONFIG` überschreibbar), kein Verzeichnis-Merge in 0.1. **`--validate` Dry-Run**: lädt+validiert vollständig, konkrete Fehlermeldung (Target+Feld), Exit ≠ 0, startet keine Probes → CI/GitOps-tauglich. Flags schlank: `--config`, `--validate`, `--version`, `--log-level`, `--listen`. **Fail-fast**: ungültige Config beim Start ⇒ Sentinel startet gar nicht (kein partial start). **Erreichbarkeit ist NIE Teil der Validierung** — DNS/Reachability ist Laufzeit-Messung, nicht Config-Fehler (sonst startet Sentinel bei echten Ausfällen nicht).
- **Flags:** —

## Open flags (pending input)

Alle offenen Punkte sind **Doku-Nacharbeit** (keine echten Blocker fürs Coding) und liegen bei **Bodo** bzw. sind Teil der 0.1-Umsetzung:
- README.md / architecture.md: connection-pooling-Aussage korrigieren -> Bodo (Doku)
- architecture.md: `ProbeResult`-Definition (map) auf typisiertes Result angleichen -> Bodo (Doku)
- metrics.md: `probe_failure_info` statt `probe_failure_reason`; Histogramme als 0.2; `probe_skipped_total` ergänzen -> Bodo (Doku)
- configuration.md: Templates/Retry/Proxy/multi-level-Timeouts als 0.2 kennzeichnen; Tags-als-Labels einschränken -> Bodo (Doku)
- Roadmap.md: 0.1 auf HTTP-only reduzieren -> Bodo (Doku)
- Sicherheits-Kommentar dokumentieren, warum `InsecureSkipVerify` in der TLS-Probe korrekt ist (Code-Review-Stolperstein) -> bei Umsetzung (Q11)

_Kein offener inhaltlicher Design-Punkt — die Architektur für 0.1 ist entschieden._

**Merkposten (2026-08-02):** Nach vollständiger 0.1 eine eigene **Benchmark-Diskussion** führen (Scheduler/Store/HTTP-Probe, Last-/Speicherprofil bei Hunderten Targets, ggf. Vergleich Blackbox Exporter). Vom User angefordert; erst besprechen, dann bauen.
