# Two New XSS Cases, Explained

This document introduces the **XSStrange** project, explains the two web‑security
vulnerabilities we added, and then describes **exactly what was implemented** for each —
the files, the vulnerable code, how it runs, and how it was verified.

It is written to be read start‑to‑finish: theory first, concrete implementation second.

- Companion docs: [`IMPLEMENTATION_GUIDE.md`](./IMPLEMENTATION_GUIDE.md) is the step‑by‑step
  build guide; [`ADDED_CASES_EXPLAINED.md`](./ADDED_CASES_EXPLAINED.md) is the runtime
  "what changed" reference. This file is the **conceptual explainer**.

> ⚠️ Everything here is **deliberately vulnerable** teaching material for an isolated
> security‑training lab. The code and payloads are meant to run only inside XSStrange.

---

## 1. Introduction — what is XSStrange?

**XSStrange** is a small, self‑hosted **web‑vulnerability lab**. Its purpose is to provide a
safe, repeatable environment full of intentionally vulnerable pages so you can:

- learn how different classes of **Cross‑Site Scripting (XSS)** actually work,
- practice writing and firing payloads by hand, and
- point automated scanners at known‑vulnerable targets to observe and evaluate them.

### 1.1 How it's built

| Layer | Technology |
|---|---|
| Backend | Python **Flask** (`app.py`) |
| Frontend | Server‑rendered HTML + CSS + vanilla JS (Jinja2 templates) |
| Server‑side payloads | **PHP** (executed by a hardened `php` CLI inside the container) |
| Packaging | **Docker** (Alpine image bundles Python **and** PHP), served on port 80 |

There is **no database**. Every exercise ("case") is a single **JSON file** on disk under
`cases/`, grouped into categories. Today there are two categories:

- `cases/reflected/` — **reflected** XSS (the server echoes your input straight back), and
- `cases/dom-based/` — **DOM‑based** XSS (client‑side JavaScript mishandles a value).

### 1.2 How a "case" works

A case is a JSON document describing the exercise (title, difficulty, risk, hints,
objectives) plus the vulnerable content itself. When you open a case, Flask loads its JSON
and renders it through one template (`templates/template_pages/case_template.html`). There
are two ways the vulnerable content is produced — this distinction matters for the two
cases we added:

| `type` | Where the bug lives | How the content is produced |
|---|---|---|
| **`html`** | **In the browser** (client‑side). The JSON's `body` field is raw HTML+JS that the template outputs verbatim; the script then runs in *your* browser. | `body` is taken directly from the JSON. |
| **`php`** | **On the server.** The JSON's `php` field is PHP source; Flask runs it with your query‑string parameters injected as `$_GET`, and captures the output. | The template outputs the PHP's stdout. |

In both models the final content is emitted **without escaping** (`{{ body | safe }}` in the
template). That "no escaping" is exactly what makes the exercises exploitable — and it is
intentional for a lab.

The two cases we added use one model each:

- **PostMessage insecure‑regex** → a **DOM‑based** (`type: html`) case, and
- **JavaScript single‑quoted string** → a **reflected** (`type: php`) case.

---

## 2. The two vulnerabilities

### 2.1 PostMessage — improper origin validation with an insecure regex

#### Background: what `postMessage` is for

Browsers isolate pages from different origins (scheme + host + port) from one another. When
two windows/iframes *do* need to talk across that boundary — say, a page and an embedded
third‑party widget — they use `window.postMessage()`. The receiving side listens:

```js
window.addEventListener('message', (event) => {
  // event.origin  – WHO sent it (set by the browser; cannot be forged)
  // event.data    – WHAT they sent (fully attacker-controlled if the sender is hostile)
});
```

The browser guarantees `event.origin` is the sender's true origin. It does **not** decide
*whether you should trust that sender* — that is the receiver's job.

#### The security contract (and how it's broken)

Because **any** page on the internet can open or frame your page and post a message to it,
a receiver must do two things:

1. **Validate `event.origin`** against an allow‑list *before* trusting the data, and
2. **Use the data safely** (never route it straight into a dangerous "sink").

This vulnerability is the classic failure of **step 1**, caused specifically by validating
the origin with a **loose regular expression**, followed by a failure of **step 2** (the
data is written with `innerHTML`).

#### Why a regex is the wrong tool here

An origin check should be an **exact** comparison against a known value:

```js
if (event.origin === 'https://trusted-widget.com') { /* ok */ }   // correct
```

Developers often reach for a pattern instead — and get it subtly wrong. The check we use:

```js
/trusted-widget\.com/.test(event.origin)
```

is **not anchored** (`^ … $`), so it behaves like a **substring search**: it returns `true`
for *any* origin string that merely **contains** `trusted-widget.com`. An attacker simply
registers a domain that embeds the trusted string:

| Origin the attacker sends from | Passes `/trusted-widget\.com/`? | Why |
|---|---|---|
| `https://trusted-widget.com` | ✅ intended | the real widget |
| `https://trusted-widget.com.attacker.example` | ✅ **bypass** | attacker owns `attacker.example`; the trusted name is just a sub‑label |
| `https://nottrusted-widget.com` | ✅ **bypass** | a look‑alike that still *contains* the substring |
| `https://random-unrelated.com` | ❌ rejected | doesn't contain the string — proving the check does *something* |

The last row matters pedagogically: the gate is **not absent**, it is **bypassable**. That
is the real‑world shape of the bug.

> The same class of flaw appears as: missing `^`/`$` anchors, an **unescaped dot**
> (`/trusted-widget.com/` where `.` matches any character), `origin.indexOf('…') !== -1`,
> `origin.startsWith('https://trusted-widget.com')` (matches `…com.evil.io`), or
> `origin.endsWith('trusted-widget.com')` (matches `eviltrusted-widget.com`).

#### The sink and the impact

Once the weak check is bypassed, the attacker's `event.data` reaches:

```js
document.getElementById('widget-output').innerHTML = event.data;   // dangerous sink
```

Writing attacker‑controlled data with `innerHTML` renders it as **live HTML**, so a payload
like `<img src=x onerror="alert(document.domain)">` executes JavaScript in the victim
page's origin — **DOM‑based XSS**. Real impact: session/token theft, account actions on the
victim's behalf, UI spoofing, etc.

*(Note: `innerHTML` will not run a bare `<script>` element, which is why payloads use
self‑firing elements such as `<img onerror>` or `<svg onload>`.)*

#### The fix

```js
const ALLOWED = 'https://trusted-widget.com';
window.addEventListener('message', (event) => {
  if (event.origin !== ALLOWED) return;               // exact allow-list match
  if (typeof event.data !== 'string') return;         // validate shape
  document.getElementById('widget-output').textContent = event.data;  // safe sink
});
```

---

### 2.2 Reflected XSS into a single‑quoted JavaScript string

#### Background: reflected XSS

A **reflected** XSS happens when the server takes input from the request and writes it
straight back into the response **without encoding it for the context** it lands in. The
payload isn't stored; it's "reflected" from the request into the page and executed in the
victim's browser (typically delivered via a crafted link).

#### The specific context: inside a single‑quoted string literal

Here the reflected value lands **inside a single‑quoted JavaScript string**:

```php
var user = '<?php echo $input; ?>';   //  $input is $_GET['q'], echoed with NO encoding
```

If the input is ordinary text, this is harmless: `var user = 'guest';`. But because the
value is dropped between quotes **unescaped**, the attacker controls the bytes inside the
string. The delimiter protecting the value is a single quote `'`, so the attack is to
**supply a single quote** that terminates the string early, then write real JavaScript.

#### Breaking out

Given the sink `var user = '<INPUT>';`, two standard payloads:

| Input for `q` | Resulting JavaScript | Why it runs |
|---|---|---|
| `'; alert(document.domain); //` | `var user = ''; alert(document.domain); //';` | close the string, run a statement, then `//` comments out the leftover `';` |
| `'-alert(document.domain)-'` | `var user = ''-alert(document.domain)-'';` | no comment needed — `alert` runs as a side effect while the line stays valid |

#### Why the quote style matters

In a **single**‑quoted context a `'` breaks out but a `"` does not. A common half‑fix that
only escapes double quotes leaves this context fully exploitable — which is why the
single‑quoted case is worth demonstrating distinctly from a double‑quoted or unquoted one.
Correctly defending a value that lands in JavaScript depends on knowing the exact
delimiter.

#### The fix

HTML‑encoding (`htmlspecialchars`) is **wrong** for a JS‑string context. Emit the value as
a safe JavaScript literal with `json_encode`, which supplies the quotes *and* escapes
everything dangerous:

```php
// json_encode produces the quotes AND the escaping — never hand-wrap in quotes.
var user = <?php echo json_encode($input, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
```

---

## 3. Exactly what was implemented

Two new case files were added — **content only**. No Python or template code was changed:
both cases run on the existing case route and template, exactly like their siblings.

| File | Category | `type` | Vulnerability |
|---|---|---|---|
| `cases/dom-based/postmessage-insecure-regex.json` | dom‑based | `html` | insecure‑regex `postMessage` origin check → `innerHTML` sink |
| `cases/reflected/js-single-quoted.json` | reflected | `php` | `?q=` reflected into a single‑quoted JS string |

Both were also registered in the `templates/index_cases.json` manifest (the by‑convention
registry the other cases use).

### 3.1 `postmessage-insecure-regex` (DOM‑based, `type: html`)

**URL:** `/cases/dom-based/postmessage-insecure-regex/`

The heart of the case is the `body` field — raw HTML+JS that the browser runs. Read
un‑minified, the vulnerable script is:

```js
// Intended sender: https://trusted-widget.com
// INSECURE origin check: an unanchored regex behaves like a substring match.
// It returns true for ANY origin that merely CONTAINS 'trusted-widget.com', e.g.
//   https://trusted-widget.com.attacker.example   (attacker-controlled suffix)
function isOriginTrusted(origin) {
  return /trusted-widget\.com/.test(origin);           // ← the flaw (unanchored regex)
}
window.addEventListener('message', function (event) {
  if (!isOriginTrusted(event.origin)) {
    console.warn('Rejected message from origin:', event.origin);
    return;
  }
  // Vulnerable SINK: attacker-controlled data written as HTML.
  document.getElementById('widget-output').innerHTML = event.data;
});
```

**How it runs:** the page registers itself as a `postMessage` receiver. When a message
arrives, the origin is checked with the unanchored regex; if it passes, `event.data` is
written into the page with `innerHTML`. Because this is pure client‑side code, the case is
driven from the browser (DevTools), matching the site's other DOM cases like
`window-name-eval`.

**How to trigger it (DevTools console):**

```js
// Simulates a message from an attacker origin that satisfies the bad regex.
window.dispatchEvent(new MessageEvent('message', {
  origin: 'https://trusted-widget.com.attacker.example',
  data:   '<img src=x onerror="alert(document.domain)">'
}));
```

The `alert` fires because the look‑alike origin passes the substring check and the `<img>`
runs via `innerHTML`. *(You cannot forge `event.origin` over a real `postMessage`, so
`dispatchEvent` is the deterministic way to drive the vulnerable path locally; a true
cross‑origin attacker page would be served from a host whose origin contains the trusted
string.)*

**The complete file:**

```json
{
  "title": "PostMessage Insecure Regex Origin Check",
  "description": "A message receiver validates event.origin with an unanchored regex (a substring match) and writes event.data into the DOM via innerHTML. Any origin that merely contains the trusted string is accepted.",
  "objectives": [
    "Identify the message event handler and the origin allow-list it relies on.",
    "Explain why the regex /trusted-widget\\.com/ accepts an attacker-controlled origin.",
    "Deliver a payload through event.data that executes JavaScript via the innerHTML sink."
  ],
  "hints": [
    "The origin check is /trusted-widget\\.com/.test(event.origin) — it is unanchored, so it is really a substring match.",
    "An origin such as https://trusted-widget.com.attacker.example satisfies that regex.",
    "innerHTML will not run a bare <script>; use a self-firing element, e.g. <img src=x onerror=alert(document.domain)>.",
    "Simulate the attacker's origin from DevTools: window.dispatchEvent(new MessageEvent('message', { origin: 'https://trusted-widget.com.attacker.example', data: '<img src=x onerror=alert(document.domain)>' }))"
  ],
  "difficulty": "medium",
  "category": "dom-based",
  "risk": "high",
  "status": "active",
  "type": "html",
  "body": "<h3>Trusted Widget Receiver</h3>...<script> /* the handler shown above */ </script>"
}
```

*(The `body` value is stored as a single JSON string; it is shown abbreviated here — the
verbatim, copy‑ready JSON is in `IMPLEMENTATION_GUIDE.md` and in the file itself.)*

### 3.2 `js-single-quoted` (reflected, `type: php`)

**URL:** `/cases/reflected/js-single-quoted/?q=<payload>`

The heart of the case is the `php` field. Its output places `$_GET['q']` inside a
single‑quoted JavaScript string with no encoding. Un‑minified:

```php
<?php
$input = isset($_GET['q']) ? $_GET['q'] : 'guest';
?>
<!DOCTYPE html>
<html>
<body>
    <h3>PHP to JavaScript Single-Quoted String</h3>
    <p>The <code>q</code> parameter is reflected inside a <b>single-quoted</b> JavaScript string.</p>
    <p>Param: <code>?q=</code></p>

    <script>
        // INJECTION POINT: your input lands between the single quotes.
        var user = '<?php echo $input; ?>';
        document.getElementById('greeting').textContent = 'Welcome back, ' + user + '!';
    </script>

    <p id='greeting'></p>
    <p>Terminate the single-quoted string, run your own JavaScript, then keep the script valid.</p>
</body>
</html>
```

**How it runs:** Flask executes this PHP with `q` injected as `$_GET['q']`, captures the
generated HTML, and returns it. The browser then runs the `<script>`. If `q` contained a
`'`, the string terminated early and the attacker's JavaScript executes. This matches the
site's other reflected/PHP cases (`js-quoted`, `js-unquoted`, `js-eval`), which are also
driven through the URL query string.

**How to trigger it (URL, values URL‑encoded, keep the trailing slash before `?`):**

| Payload for `q` | Test URL |
|---|---|
| `'; alert(document.domain);//` | `/cases/reflected/js-single-quoted/?q=%27%3B%20alert(document.domain)%3B%2F%2F` |
| `'-alert(document.domain)-'` | `/cases/reflected/js-single-quoted/?q=%27-alert(document.domain)-%27` |

**The complete file:**

```json
{
  "title": "PHP JavaScript Single-Quoted String",
  "description": "Reflects the q parameter from PHP directly inside a single-quoted JavaScript string literal, with no output encoding.",
  "category": "reflected",
  "difficulty": "Medium",
  "risk": "High",
  "status": "Active",
  "type": "php",
  "php": "<?php ... var user = '<?php echo $input; ?>'; ... ?>",
  "objectives": [
    "Terminate the single-quoted string that wraps the q value with a single quote.",
    "Inject and execute your own JavaScript, e.g. alert(document.domain).",
    "Keep the remaining script syntactically valid (comment out or absorb the trailing quote)."
  ],
  "hints": [
    "The context is: var user = '[INPUT]'; produced by PHP.",
    "A double quote won't help here — the delimiter is a single quote.",
    "Break the string, add your payload, then comment out the rest: '; alert(document.domain);//",
    "Or use the arithmetic form that needs no comment: '-alert(document.domain)-'"
  ]
}
```

*(The `php` value is stored as a single JSON string; shown abbreviated — the verbatim file
is in the repo and in `IMPLEMENTATION_GUIDE.md`.)*

### 3.3 Consistency with the rest of the site

Both cases were built to be indistinguishable in structure from their neighbors:

- **`js-single-quoted`** uses the **same key order and Title‑case metadata**
  (`Medium`/`High`/`Active`, `type: php`, a `php` field) as `js-eval`, `js-quoted`, and
  `js-unquoted`.
- **`postmessage-insecure-regex`** uses the **same key order and lowercase metadata**
  (`medium`/`high`/`active`, `type: html`, a `body` field) as `window-name-*`, `cookie-*`,
  and `localstorage-*`.
- Neither adds any code path — they reuse the existing `case` route and
  `case_template.html`, so they automatically inherit the site's metadata badges,
  objectives/hints panels, and category listing.

### 3.4 What was verified

Both cases were tested end‑to‑end in the Docker container (PHP 8.3):

| Case | Verification | Result |
|---|---|---|
| postmessage | Handler logic executed in Node.js | attacker look‑alike origin → payload **reached `innerHTML`**; unrelated origin **rejected**; real trusted origin passes ✅ |
| js‑single‑quoted | Live HTTP render, default | `var user = 'guest';` (PHP executes) ✅ |
| js‑single‑quoted | Live HTTP render, breakout `'; alert…//` | `var user = ''; alert(document.domain);//';` ✅ |
| js‑single‑quoted | Live HTTP render, arithmetic `'-alert-'` | `var user = ''-alert(document.domain)-'';` ✅ |
| both | Category listing + detail pages | listed with correct **PHP/HTML** and **risk** badges; HTTP 200 ✅ |
| both | JSON validity + manifest membership | valid JSON; present in `index_cases.json` ✅ |

---

## 4. Try it yourself

With the container running (`docker compose up -d --build`, served on `http://127.0.0.1/`):

- **DOM case:** open `http://127.0.0.1/cases/dom-based/postmessage-insecure-regex/`, then
  paste the DevTools `dispatchEvent` snippet from §3.1.
- **Reflected case (fires on page load):**
  `http://127.0.0.1/cases/reflected/js-single-quoted/?q=%27%3B%20alert(document.domain)%3B%2F%2F`

Stop the lab when done with `docker compose down`.
