"""Small browser demo wrapping the existing five-context gateway."""
from __future__ import annotations

from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from demo import BALANCE_TASK, WARN_POLICY, balance_call, transfer_call
from gateway import BalanceGateway, SolanaDevnetAdapter

app = FastAPI(title="MCP-Consist Security Workbench", docs_url=None, redoc_url=None, openapi_url=None)
adapter = SolanaDevnetAdapter()
gateway = BalanceGateway(adapter=adapter)


class ScenarioRequest(BaseModel):
    address: str = Field(min_length=1, max_length=44)


class ApprovalRequest(BaseModel):
    approval_id: str = Field(min_length=8, max_length=64)


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse(DASHBOARD_HTML)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "mcp-consist-solana-demo"}


@app.post("/api/scenarios/{scenario}")
def run_scenario(scenario: Literal["allow", "block", "warn"], request: ScenarioRequest) -> dict:
    if scenario == "allow":
        call = balance_call(request.address)
        policy = None
    elif scenario == "block":
        call = transfer_call(request.address)
        policy = None
    else:
        call = balance_call(request.address)
        policy = WARN_POLICY
    context = gateway.build_context(BALANCE_TASK, call, policy)
    before = adapter.dispatch_count
    try:
        outcome = gateway.propose(request.address, user_task=BALANCE_TASK, policy=policy, proposed_call=call)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "scenario": scenario,
        "context": context,
        "outcome": outcome,
        "adapter_dispatches": adapter.dispatch_count - before,
        "adapter_dispatch_total": adapter.dispatch_count,
    }


@app.post("/api/approve")
def approve(request: ApprovalRequest) -> dict:
    pending = gateway.pending.get(request.approval_id)
    if pending is None:
        raise HTTPException(status_code=404, detail="Approval request not found or already used")
    context = dict(pending.context)
    before = adapter.dispatch_count
    try:
        outcome = gateway.approve(request.approval_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "scenario": "warn-approval",
        "context": context,
        "outcome": outcome,
        "adapter_dispatches": adapter.dispatch_count - before,
        "adapter_dispatch_total": adapter.dispatch_count,
    }


DASHBOARD_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#101113"><title>MCP-Consist · Security Workbench</title>
<style>
:root{color-scheme:dark;--bg:#101113;--panel:#17191c;--panel2:#1d2024;--line:#30343a;--text:#f2f0eb;--muted:#a3a6aa;--amber:#e0ad4f;--green:#8bd2aa;--red:#ed8e85;--warn:#e7bc63;--mono:ui-monospace,SFMono-Regular,Menlo,monospace;--sans:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 var(--sans)}button,input{font:inherit}a{color:var(--amber);text-decoration:none}.shell{max-width:1200px;margin:auto;padding:28px 28px 64px}.top{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);padding:0 0 22px}.brand{display:flex;align-items:center;gap:13px}.mark{width:38px;height:38px;border:1px solid #7c612e;border-radius:10px;display:grid;place-items:center;color:var(--amber);font-weight:750;font-size:19px}.brand strong{display:block;font-size:16px;letter-spacing:.02em}.brand small,.eyebrow{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.14em}.status{display:flex;align-items:center;gap:9px;color:#b5bbb5;font-size:12px}.dot{height:8px;width:8px;border-radius:50%;background:var(--green);box-shadow:0 0 0 3px #8bd2aa1b}.hero{padding:46px 0 28px;display:grid;grid-template-columns:1.25fr .75fr;gap:40px;align-items:end}.eyebrow{color:var(--amber)}h1{font-size:clamp(32px,5vw,54px);line-height:1.07;letter-spacing:-.045em;margin:12px 0 14px;max-width:720px}.intro{color:#b7b8b8;max-width:660px;margin:0}.proof{border:1px solid #765c2e;background:#1b1915;border-radius:12px;padding:20px 22px}.proof .label{font-size:11px;letter-spacing:.14em;color:#c99e50;text-transform:uppercase}.proof .claim{font:700 clamp(24px,3vw,36px)/1.1 var(--mono);margin-top:9px;letter-spacing:-.06em}.proof .explain{font-size:12px;color:#aaa399;margin-top:8px}.control,.result,.contexts{background:var(--panel);border:1px solid var(--line);border-radius:12px}.control{padding:20px;margin:10px 0 20px}.controlhead{display:flex;justify-content:space-between;gap:18px;align-items:flex-start}.control h2,.sectiontitle{font-size:14px;margin:0 0 5px}.sub{color:var(--muted);font-size:12px}.inputrow{display:flex;gap:10px;margin-top:17px}.inputrow input{flex:1;min-width:0;background:#101214;border:1px solid #383c42;border-radius:8px;color:var(--text);padding:11px 13px;font:13px var(--mono)}button{cursor:pointer;border:1px solid #765c2e;background:#292319;color:#f5d18b;padding:10px 14px;border-radius:8px;font-weight:650}button:hover{background:#342b1b;border-color:var(--amber)}button:disabled{opacity:.55;cursor:wait}.scenarios{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:0 0 20px}.scenario{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:17px}.scenario h3{margin:0 0 5px;font-size:14px}.scenario p{margin:0 0 13px;color:var(--muted);font-size:12px;min-height:36px}.scenario button{width:100%;font-size:12px}.result{padding:21px;margin-bottom:20px;min-height:160px}.empty{color:var(--muted);display:grid;place-items:center;min-height:120px;text-align:center}.resulttop{display:flex;justify-content:space-between;align-items:center;gap:12px;border-bottom:1px solid var(--line);padding-bottom:15px;margin-bottom:15px}.verdict{display:flex;align-items:center;gap:10px;font-weight:800;letter-spacing:.1em}.badge{font:700 11px var(--mono);padding:5px 8px;border-radius:5px;background:#24272a;color:var(--muted)}.allow{color:var(--green)}.block{color:var(--red)}.warn{color:var(--warn)}.dispatch{font:12px var(--mono);color:#d8dadd}.dispatch b{color:var(--text);font-size:15px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.box{border:1px solid var(--line);background:#121416;border-radius:8px;padding:13px;min-width:0}.box h4{margin:0 0 8px;color:#b7b9bb;font-size:10px;text-transform:uppercase;letter-spacing:.12em}.box pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;color:#ddd;font:11px/1.5 var(--mono);max-height:210px;overflow:auto}.findings{grid-column:1/-1}.findings ul{margin:0;padding-left:18px;color:#d2d0ca;font-size:13px}.findings li+li{margin-top:5px}.findings .none{color:var(--muted);list-style:none;margin-left:-18px}.resultdata{grid-column:1/-1}.approval{margin-top:13px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}.approval span{color:var(--warn);font-size:12px}.contexts{padding:20px}.contexts-head{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:13px}.contextlist{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}.ctx{padding:11px 10px;background:#121416;border:1px solid var(--line);border-radius:8px;min-height:66px}.ctx b{display:block;font-size:11px;color:#e3c17e;margin-bottom:4px}.ctx span{font-size:10px;color:var(--muted)}.footer{margin-top:25px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:11px;display:flex;justify-content:space-between;gap:15px;flex-wrap:wrap}.error{color:var(--red);font-size:13px}@media(max-width:760px){.shell{padding:18px 15px 40px}.hero{grid-template-columns:1fr;gap:19px;padding-top:34px}.scenarios{grid-template-columns:1fr}.scenario p{min-height:0}.contextlist{grid-template-columns:1fr 1fr}.grid{grid-template-columns:1fr}.findings,.resultdata{grid-column:auto}.inputrow{flex-direction:column}.inputrow button{width:100%}.top{align-items:flex-start}.status{font-size:10px}.resulttop{align-items:flex-start;flex-direction:column}}
</style></head>
<body><main class="shell">
<header class="top"><div class="brand"><div class="mark">M</div><div><strong>MCP-CONSIST</strong><small>Solana Devnet · Security research workbench</small></div></div><div class="status"><i class="dot"></i> Gateway online · read-only</div></header>
<section class="hero"><div><div class="eyebrow">Pre-execution analysis</div><h1>Evaluate the call before it reaches the chain.</h1><p class="intro">Five-context analysis gates one read-only balance tool. Decisions come from the existing MCP-Consist engine; only ALLOW reaches Solana Devnet.</p></div><aside class="proof"><div class="label">Execution guard</div><div class="claim">BLOCK → ZERO DISPATCHES</div><div class="explain">The transfer-shaped proposal is evaluated by the real engine. The adapter counter below reports this run.</div></aside></section>
<section class="control"><div class="controlhead"><div><h2>Account under review</h2><div class="sub">Enter a base58 Solana public key. The Devnet balance request is read-only.</div></div><span class="badge">DEVNET ONLY</span></div><div class="inputrow"><input id="address" value="11111111111111111111111111111111" aria-label="Solana account address" spellcheck="false"><button id="runAllow" onclick="runScenario('allow')">Run balance check</button></div></section>
<section class="scenarios" aria-label="Security scenarios"><article class="scenario"><h3>01 · Authorized read</h3><p>Balance lookup matches the user task and read policy.</p><button onclick="runScenario('allow')">Evaluate and query Devnet</button></article><article class="scenario"><h3>02 · Transfer-shaped proposal</h3><p>Proposed write exceeds the read-only tool capability.</p><button onclick="runScenario('block')">Evaluate blocked proposal</button></article><article class="scenario"><h3>03 · Policy coverage gap</h3><p>One policy field is omitted; WARN requires explicit approval.</p><button onclick="runScenario('warn')">Evaluate warning</button></article></section>
<section id="result" class="result" aria-live="polite"><div class="empty">Run a scenario to see its actual engine verdict, findings, five contexts, and adapter dispatch count.</div></section>
<section class="contexts"><div class="contexts-head"><h2 class="sectiontitle">Five-context evaluation</h2><span class="sub">All five are passed to analyze()</span></div><div class="contextlist"><div class="ctx"><b>01 · Description</b><span>Advertised tool purpose</span></div><div class="ctx"><b>02 · Schema</b><span>Declared address input</span></div><div class="ctx"><b>03 · Capability policy</b><span>Permitted tools and actions</span></div><div class="ctx"><b>04 · User task</b><span>Balance lookup intent</span></div><div class="ctx"><b>05 · Proposed call</b><span>Tool, action, and arguments</span></div></div></section>
<footer class="footer"><span>Deterministic research prototype · not a production security boundary</span><span>No signing · no transactions · no private keys · no Mainnet</span></footer>
</main><script>
const resultBox=document.getElementById('result');
function esc(v){return String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function format(v){return JSON.stringify(v,null,2)}
function renderError(message){resultBox.innerHTML='<div class="error">'+esc(message)+'</div>'}
function render(data){const out=data.outcome||{};const analysis=out.analysis||{};const verdict=out.decision||'ERROR';const klass=verdict.toLowerCase();const findings=analysis.findings||[];const findingHtml=findings.length?'<ul>'+findings.map(f=>'<li><b>'+esc(f.rule_id)+' · '+esc(f.severity)+'</b> — '+esc(f.description)+'</li>').join('')+'</ul>':'<ul><li class="none">No findings.</li></ul>';const contexts=data.context||{};let rpc='';if(out.result)rpc='<div class="box resultdata"><h4>Actual Devnet result</h4><pre>'+esc(format(out.result))+'</pre></div>';else if(out.error)rpc='<div class="box resultdata"><h4>Execution result</h4><pre>'+esc(out.status+': '+out.error)+'</pre></div>';let approval='';if(out.status==='approval_required'&&out.approval_id){approval='<div class="approval"><button id="approveButton" onclick="approve(\''+esc(out.approval_id)+'\')">Approve this read-only lookup</button><span>No adapter dispatch occurred before approval.</span></div>'}resultBox.innerHTML='<div class="resulttop"><div class="verdict '+klass+'">'+esc(verdict)+' <span class="badge">'+esc(out.status||'')+'</span></div><div class="dispatch">Adapter dispatches this run: <b>'+esc(data.adapter_dispatches)+'</b> · total: '+esc(data.adapter_dispatch_total)+'</div></div><div class="grid"><div class="box"><h4>User task</h4><pre>'+esc(contexts.task||'')+'</pre></div><div class="box"><h4>Proposed tool call</h4><pre>'+esc(contexts.call||'')+'</pre></div><div class="box"><h4>Findings</h4>'+findingHtml+'</div><div class="box"><h4>Engine trace</h4><pre>'+esc(format(analysis.trace||[]))+'</pre></div><div class="box"><h4>Tool description</h4><pre>'+esc(contexts.description||'')+'</pre></div><div class="box"><h4>Tool schema</h4><pre>'+esc(contexts.schema||'')+'</pre></div><div class="box"><h4>Capability policy</h4><pre>'+esc(contexts.policy||'')+'</pre></div>'+rpc+'</div>'+approval}
async function runScenario(name){const buttons=[...document.querySelectorAll('button')];buttons.forEach(b=>b.disabled=true);resultBox.innerHTML='<div class="empty">Evaluating with the existing engine…</div>';try{const response=await fetch('/api/scenarios/'+name,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:document.getElementById('address').value.trim()})});const data=await response.json();if(!response.ok)throw new Error(data.detail||'Request failed');render(data)}catch(e){renderError(e.message)}finally{buttons.forEach(b=>b.disabled=false)}}
async function approve(id){const button=document.getElementById('approveButton');if(button)button.disabled=true;try{const response=await fetch('/api/approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({approval_id:id})});const data=await response.json();if(!response.ok)throw new Error(data.detail||'Approval failed');render(data)}catch(e){renderError(e.message)}}
runScenario('block');
</script></body></html>'''
