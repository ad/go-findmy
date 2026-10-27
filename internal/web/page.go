package web

const pageHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Find My</title>
<style>
:root{color-scheme:light dark;--bg:#f4f5f7;--card:#fff;--text:#1c1c1e;--muted:#5f6672;--line:#dfe2e7;--accent:#0277bd;--on-accent:#fff;--err:#c62828;--warn:#b45309;--ok:#2e7d32}
@media (prefers-color-scheme:dark){:root{--bg:#111318;--card:#1c1e24;--text:#e6e7ea;--muted:#9aa0aa;--line:#2f323a;--accent:#4fc3f7;--on-accent:#06202e;--err:#ff7b72;--warn:#f0b45a;--ok:#6fcf74}}
*{box-sizing:border-box}
body{margin:0;padding:1rem;background:var(--bg);color:var(--text);font:16px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:40rem;margin:0 auto}
header{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem 1rem;margin:.25rem 0 1rem}
h1{font-size:1.5rem;margin:0;flex:1}
h2{font-size:1.1rem;margin:0 0 .25rem}
p{margin:.4rem 0}
.muted{color:var(--muted);font-size:.9rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1rem;margin:0 0 1rem}
.pill{display:inline-flex;align-items:center;gap:.4rem;padding:.15rem .7rem;border-radius:999px;font-size:.85rem;font-weight:600;border:1px solid currentColor;color:var(--muted)}
.pill::before{content:"";width:.5rem;height:.5rem;border-radius:50%;background:currentColor}
.pill.ok{color:var(--ok)}.pill.warn{color:var(--warn)}.pill.err{color:var(--err)}
.banner{border-left:4px solid var(--muted);border-radius:8px;padding:.6rem .8rem;margin:0 0 1rem;background:color-mix(in srgb,var(--muted) 12%,var(--card))}
.banner.ok{border-color:var(--ok);background:color-mix(in srgb,var(--ok) 14%,var(--card))}
.banner.warn{border-color:var(--warn);background:color-mix(in srgb,var(--warn) 14%,var(--card))}
.banner.err{border-color:var(--err);background:color-mix(in srgb,var(--err) 14%,var(--card))}
.steps{display:flex;gap:.5rem;list-style:none;padding:0;margin:0 0 1rem;counter-reset:s}
.steps li{flex:1;counter-increment:s;display:flex;align-items:center;gap:.5rem;font-size:.9rem;color:var(--muted)}
.steps li::before{content:counter(s);display:grid;place-items:center;flex:none;width:1.6rem;height:1.6rem;border-radius:50%;border:1px solid var(--line);font-weight:600}
.steps .current{color:var(--text);font-weight:600}
.steps .current::before{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.steps .done::before{content:"\2713";background:var(--ok);border-color:var(--ok);color:var(--card)}
label{display:block;margin:.8rem 0 .25rem;font-size:.9rem;font-weight:600}
label.check{display:flex;gap:.5rem;align-items:flex-start;font-weight:400;margin:.8rem 0 0}
input,textarea{display:block;width:100%;padding:.55rem .7rem;font:inherit;color:var(--text);background:var(--bg);border:1px solid var(--line);border-radius:8px}
input[type=checkbox]{width:auto;margin-top:.2rem;accent-color:var(--accent)}
input:focus,textarea:focus,button:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
textarea{font:.85rem/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;resize:vertical}
input.code{font-size:1.6rem;letter-spacing:.4em;text-align:center;max-width:14rem}
button{font:inherit;font-weight:600;cursor:pointer;padding:.55rem 1.1rem;border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:var(--on-accent)}
button.link{border-color:transparent;background:none;color:var(--accent);padding-left:.4rem;padding-right:.4rem}
button:disabled{opacity:.5;cursor:not-allowed}
.actions{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem 1rem;margin-top:1rem}
.actions form{margin:0}
details>summary{cursor:pointer;font-weight:600;list-style-position:inside}
details[open]>summary{margin-bottom:.5rem}
.tags{list-style:none;margin:0;padding:0}
.tags li{display:flex;flex-wrap:wrap;justify-content:space-between;gap:.1rem 1rem;padding:.6rem 0;border-top:1px solid var(--line)}
.tags li:first-child{border-top:0}
.tags b{font-weight:600}
a{color:var(--accent)}
</style>
<script>
(function(){
var map={'--primary-background-color':'--bg','--card-background-color':'--card','--primary-text-color':'--text','--secondary-text-color':'--muted','--divider-color':'--line','--primary-color':'--accent','--text-primary-color':'--on-accent','--error-color':'--err','--warning-color':'--warn','--success-color':'--ok'};
function apply(){
 try{
  var cs=parent.getComputedStyle(parent.document.documentElement),r=document.documentElement.style;
  for(var k in map){var v=cs.getPropertyValue(k).trim();if(v)r.setProperty(map[k],v)}
 }catch(e){}
}
apply();
try{new MutationObserver(apply).observe(parent.document.documentElement,{attributes:true,attributeFilter:['style']})}catch(e){}
})();
</script></head><body><main>
<header><h1>Find My</h1>
{{if eq .Step "code"}}<span class="pill warn">Waiting for the code</span>
{{else if eq .Step "login"}}<span class="pill err">Sign-in required</span>
{{else if .Cooldown}}<span class="pill warn">Paused</span>
{{else}}<span class="pill ok">Signed in</span>{{end}}</header>

{{with .Message}}<div class="banner {{if $.Failed}}err{{else}}ok{{end}}" role="status">{{.}}</div>{{end}}
{{with .Cooldown}}<div class="banner warn"><b>Nothing is sent to Apple for now.</b><br>{{.}}</div>{{end}}
{{with .LastError}}{{if eq $.Step "ready"}}<div class="banner err"><b>The last poll failed.</b><br>{{.}}</div>{{end}}{{end}}

{{with .Steps}}<ol class="steps">{{range .}}<li class="{{.State}}">{{.Name}}</li>{{end}}</ol>{{end}}

{{if eq .Step "login"}}
<section class="card">
<h2>Sign in with your Apple ID</h2>
<p class="muted">The add-on uses your account to fetch AirTag locations. Apple will list one more Mac in your device list: it is this add-on.</p>
{{with .Reason}}<p class="muted">Why you see this: {{.}}</p>{{end}}
{{template "loginform" .}}
</section>

{{else if eq .Step "code"}}
<section class="card">
<h2>Enter the confirmation code</h2>
<p>{{if .SMS}}Apple sent a code by SMS to your trusted phone number.{{else}}Apple showed a code on your trusted device. Look for the sign-in request there.{{end}}</p>
<form method="post" action="code">
<label for="code">6-digit code</label>
<input id="code" class="code" name="code" inputmode="numeric" pattern="[0-9]*" maxlength="8" autocomplete="one-time-code" autofocus required>
<div class="actions"><button>Confirm</button></div>
</form>
<form method="post" action="cancel" class="actions"><span class="muted">No code?</span><button class="link">Start over</button></form>
</section>

{{else}}
{{if .Tags}}
<section class="card">
<h2>Tags</h2>
<ul class="tags">{{range .Tags}}<li><b>{{.Name}}</b>{{with .Report}}<span class="muted">{{.Time.Format "2006-01-02 15:04 MST"}} · <a href="https://www.openstreetmap.org/?mlat={{.Latitude}}&amp;mlon={{.Longitude}}#map=16/{{.Latitude}}/{{.Longitude}}" target="_blank" rel="noopener noreferrer">{{.Latitude}}, {{.Longitude}}</a> · ±{{.Accuracy}} m</span>{{else}}<span class="muted">no report yet</span>{{end}}</li>{{end}}</ul>
</section>
<details class="card"><summary>Add a tag</summary>{{template "importform" .}}</details>
{{else}}
<section class="card">
<h2>Add your first tag</h2>
{{template "importform" .}}
</section>
{{end}}
<details class="card"><summary>Account</summary>
<p class="muted">Last poll: {{if .LastPoll.IsZero}}not yet{{else}}{{.LastPoll.Format "2006-01-02 15:04:05 MST"}}{{end}}</p>
<p>To switch to another Apple ID, or to renew the session, sign in again.</p>
{{template "loginform" .}}
</details>
{{end}}

<script>
document.querySelectorAll('form').forEach(function(f){f.addEventListener('submit',function(){var b=f.querySelector('button');if(b)setTimeout(function(){b.disabled=true;b.textContent='Working…'})})});
document.querySelectorAll('input[type=file][data-fill]').forEach(function(i){i.addEventListener('change',function(){var f=i.files[0];if(f)f.text().then(function(t){document.getElementById(i.dataset.fill).value=t})})});
</script>
</main></body></html>
{{define "loginform"}}<form method="post" action="login">
<label for="apple_id">Apple ID</label>
<input id="apple_id" name="apple_id" type="email" autocomplete="username" required>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<label class="check"><input name="sms" type="checkbox"><span>Send the code by SMS instead of showing it on a trusted device<br><span class="muted">Ticked automatically when the account has no trusted device.</span></span></label>
<div class="actions"><button{{if .Cooldown}} disabled{{end}}>Sign in</button>{{if .Cooldown}}<span class="muted">Wait until the pause ends.</span>{{end}}</div>
</form>{{end}}
{{define "importform"}}<p class="muted">Paste the JSON of one tag or of all of them (a list, like airtags.json), or pick the file. See the Documentation tab on how to export your AirTag keys once.</p>
<form method="post" action="import">
<label for="accessory">Tag JSON</label>
<textarea id="accessory" name="accessory" rows="7" placeholder="FindMy.py / export-findmy accessory JSON, one tag or a list" required></textarea>
<label for="accessory-file">or choose a file</label>
<input id="accessory-file" type="file" accept=".json,application/json" data-fill="accessory">
<div class="actions"><button>Import</button></div>
</form>{{end}}
`
