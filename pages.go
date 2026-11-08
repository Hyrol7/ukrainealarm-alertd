package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"html/template"
	"net/http"
	"strconv"
	"time"
)

//go:embed www/page.tmpl
var pageTmplSrc string

var pageTmpl = template.Must(template.New("page").Funcs(template.FuncMap{"inc": func(i int) int { return i + 1 }}).Parse(pageTmplSrc))

// liveScript — єдиний скрипт: раз на 10 с бере з /s три слова (загальний стан, webhook,
// звірка) і перефарбовує крапки. Якщо сервіс не відповідає — показує offline.
// Дозволений у CSP лише за точним хешем, тож інший код на сторінці не виконається.
const liveScript = `(()=>{const d=document,g=i=>d.getElementById(i),V={ok:1,warn:1,bad:1},` +
	`L={ok:"online",warn:"degraded",bad:"offline"},set=(e,c)=>{if(e)e.className="dot "+c};` +
	`async function t(){if(d.hidden)return;try{const r=await fetch("/s",{cache:"no-store"});` +
	`if(!r.ok)throw 0;const[o,h,s]=(await r.text()).trim().split(" ");if(!V[o]||!V[h]||!V[s])throw 0;` +
	`set(g("d0"),o+(o==="ok"?" pulse":""));g("l0").textContent=L[o];set(g("d1"),h);set(g("d2"),s)}` +
	`catch(e){set(g("d0"),"bad");g("l0").textContent="offline"}}` +
	`setInterval(t,10000);d.addEventListener("visibilitychange",t)})();`

var liveScriptHash = func() string {
	h := sha256.Sum256([]byte(liveScript))
	return "sha256-" + base64.StdEncoding.EncodeToString(h[:])
}()

type pageData struct {
	Code    int
	Label   string
	Dot     string // ok | warn | bad | off
	Pulse   bool
	Pair    []string // два маленькі індикатори без підписів (лише на головній)
	Title   string
	Text    string
	Refresh bool
	Script  template.JS
	Site    string // SITE_TITLE: назва вкладки; порожня — заголовок сторінки
}

// siteTitle — назва у вкладці браузера (SITE_TITLE). Задається один раз до старту серверів.
var siteTitle string

// SetSiteTitle задає назву вкладки й перерендерює сторінки помилок.
func SetSiteTitle(t string) {
	siteTitle = t
	renderedErrors = renderErrorPages()
}

// errorPages — сторінки для людей. Тексти навмисно загальні: нічого не кажуть про сервіс.
var errorPages = map[int]pageData{
	http.StatusUnauthorized:          {Title: "Без доступу.", Text: "Цей запит не пройшов перевірку.", Dot: "warn"},
	http.StatusNotFound:              {Title: "Тут нічого немає.", Text: "Такої сторінки не існує. Повертатися теж нікуди.", Dot: "warn"},
	http.StatusRequestEntityTooLarge: {Title: "Забагато.", Text: "Запит завеликий для цієї адреси.", Dot: "warn"},
	http.StatusInternalServerError:   {Title: "Щось зламалось.", Text: "Помилку записано. Її розберуть.", Dot: "bad"},
	http.StatusServiceUnavailable:    {Title: "Ще не готово.", Text: "Сервіс запускається. Спробуйте трохи згодом.", Dot: "warn"},
}

// renderedErrors — сторінки помилок рендеряться один раз на старті.
var renderedErrors = renderErrorPages()

func renderErrorPages() map[int][]byte {
	out := map[int][]byte{}
	for code, d := range errorPages {
		d.Code, d.Label, d.Site = code, strconv.Itoa(code), siteTitle
		var b bytes.Buffer
		if err := pageTmpl.Execute(&b, d); err != nil {
			panic(err)
		}
		out[code] = b.Bytes()
	}
	return out
}

const cspBase = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

func pageHeaders(h http.Header, n int) {
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", cspBase)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(n))
}

func writePage(w http.ResponseWriter, r *http.Request, code int, body []byte) {
	pageHeaders(w.Header(), len(body))
	w.WriteHeader(code)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

// errorPage віддає сторінку помилки; невідомий код — як 500.
func errorPage(w http.ResponseWriter, r *http.Request, code int) {
	b, ok := renderedErrors[code]
	if !ok {
		code, b = http.StatusInternalServerError, renderedErrors[http.StatusInternalServerError]
	}
	writePage(w, r, code, b)
}

// Стан для індикатора на головній. Значення: "ok", "warn", "bad".
type healthView struct {
	Hook, Sync, Overall string
}

// computeHealth — чиста функція (для тестів).
//
// Webhook: ok — webhook уже приходили і звірка після останнього з них не знаходила пропусків
// за останні 30 хв; warn — webhook ще жодного разу не було або звірка недавно знайшла пропуск.
// Звірка з API: ok — свіжа (до 3 інтервалів), warn — до 15 хв, bad — давніше або ще не було.
// Загалом: ok — обидва ok; bad — звірка bad і webhook не ok; інакше warn.
func computeHealth(now, lastHook, lastMiss, lastSync time.Time, syncInterval time.Duration) healthView {
	var h healthView
	switch {
	case lastHook.IsZero():
		h.Hook = "warn"
	case !lastMiss.IsZero() && lastMiss.After(lastHook) && now.Sub(lastMiss) < 30*time.Minute:
		h.Hook = "warn"
	default:
		h.Hook = "ok"
	}
	switch age := now.Sub(lastSync); {
	case lastSync.IsZero():
		h.Sync = "bad"
	case age <= 3*syncInterval+30*time.Second:
		h.Sync = "ok"
	case age <= 15*time.Minute:
		h.Sync = "warn"
	default:
		h.Sync = "bad"
	}
	switch {
	case h.Hook == "ok" && h.Sync == "ok":
		h.Overall = "ok"
	case h.Sync == "bad" && h.Hook != "ok":
		h.Overall = "bad"
	default:
		h.Overall = "warn"
	}
	return h
}

var overallLabel = map[string]string{"ok": "online", "warn": "degraded", "bad": "offline"}

func unixOrZero(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}

func (s *Server) health(now time.Time) healthView {
	return computeHealth(now, unixOrZero(s.lastHookUnix.Load()), unixOrZero(s.lastMissUnix.Load()),
		unixOrZero(s.lastSyncUnix.Load()), s.cfg.SyncInterval)
}

// serveIndex — головна: нейтральний текст і непримітний індикатор (крапка + дві маленькі
// крапки без підписів: вхідні webhook і звірка з API). Нічого конкретного не розкриває.
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	h := s.health(time.Now())
	d := pageData{
		Code: 200, Label: overallLabel[h.Overall], Dot: h.Overall, Pulse: h.Overall == "ok",
		Pair: []string{h.Hook, h.Sync}, Title: "Тут тихо.",
		Text: "Ця адреса приймає дані від машин, а не від людей.", Refresh: true, Script: template.JS(liveScript), Site: siteTitle,
	}
	var b bytes.Buffer
	if err := pageTmpl.Execute(&b, d); err != nil {
		errorPage(w, r, http.StatusInternalServerError)
		return
	}
	pageHeaders(w.Header(), b.Len())
	// головній дозволено рівно один скрипт (за хешем) і запити лише до себе
	w.Header().Set("Content-Security-Policy", cspBase+"; script-src '"+liveScriptHash+"'; connect-src 'self'")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(b.Bytes())
	}
}

// serveStatus — /s: три слова для індикатора, напр. "ok warn ok". Без подробиць.
func (s *Server) serveStatus(w http.ResponseWriter, r *http.Request) {
	h := s.health(time.Now())
	body := h.Overall + " " + h.Hook + " " + h.Sync + "\n"
	hd := w.Header()
	hd.Set("Content-Type", "text/plain; charset=utf-8")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("X-Robots-Tag", "noindex, nofollow")
	hd.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	hd.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write([]byte(body))
	}
}
