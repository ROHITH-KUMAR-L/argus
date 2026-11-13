import { useCallback, useEffect, useMemo, useState } from 'react'
import BaselinePage from './BaselinePage'
import './App.css'

type Planner = 'mock' | 'llm'
type DemoId = 'benign' | 'attack' | 'approval'
type AppPage = 'demo' | 'baseline'

interface Demo {
  id: DemoId
  title: string
  summary: string
  task_file: string
  duration: string
  goal?: string
  workspace?: string
  input_context?: string
  success_check?: { type: string; target?: string; executable?: string }
  execution_steps?: string[]
  reading_guide?: string[]
}

type CompleteDemoGuide = Demo & Required<
  Pick<Demo, 'goal' | 'workspace' | 'input_context' | 'success_check' | 'execution_steps' | 'reading_guide'>
>

interface Preflight {
  ok: boolean
  checks: Record<string, boolean>
  details: Record<string, unknown>
}

interface AppStatus {
  authority: { online: boolean; arm: string | null; started_by_web: boolean }
  planner_default: Planner
  llm_configured: boolean
  model: string | null
  preflight: Preflight | null
}

interface AuditEvent {
  seq: number
  timestamp_utc: string
  event_type: string
  action?: string
  decision?: string
  enforcement_layer?: string
  reason_code?: string
  resource?: string
  data: Record<string, unknown>
}

interface RunInfo {
  run_id: string
  task_id: string | null
  demo: DemoId | null
  planner: Planner | null
  status: string
  approval: {
    task_id: string
    expansion_id: string
    reason?: string
    delta?: unknown
  } | null
  error: string | null
  metadata: Record<string, unknown> | null
  result: {
    outcome: string
    outcome_reason: string
    independently_verified: boolean
    denials: number
    artifacts: Array<{ path: string; sha256: string }>
  } | null
  events: AuditEvent[]
  run_dir: string
}

interface RunSummary {
  run_id: string
  task_id: string | null
  demo: DemoId | null
  planner: Planner | null
  status: string
  outcome: string | null
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  const body: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    const detail =
      typeof body === 'object' && body !== null && 'detail' in body
        ? String(body.detail)
        : `Request failed with status ${response.status}`
    throw new Error(detail)
  }
  return body as T
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(value))
}

function proposalText(event: AuditEvent) {
  const proposal = event.data.proposal as Record<string, unknown> | undefined
  if (!proposal) return event.action ?? event.event_type.replaceAll('_', ' ').toLowerCase()
  const action = String(proposal.type ?? event.action ?? 'action')
  const subject = proposal.path ?? proposal.target ?? proposal.executable
  return subject ? `${action} ${String(subject)}` : action
}

function eventDetail(event: AuditEvent) {
  const proposal = event.data.proposal as Record<string, unknown> | undefined
  if (proposal?.reason) return String(proposal.reason)
  if (event.reason_code) return event.reason_code.replaceAll('_', ' ').toLowerCase()
  if (event.event_type === 'WORKER_FINISHED') {
    const data = event.data
    const output = String(data.stdout_excerpt ?? '').trim()
    return output || `Worker ${String(data.status ?? 'finished')}`
  }
  if (event.event_type === 'PRIVILEGE_EXPANSION_APPROVED') {
    return 'Approved by a human. The task continued in a new policy epoch.'
  }
  return ''
}

function eventMeaning(event: AuditEvent) {
  const meanings: Record<string, string> = {
    ACTION_PROPOSED: 'Planner intent only. The action has not run yet.',
    ACTION_ALLOWED: 'The Rust policy authority allowed this action under the current policy.',
    ACTION_DENIED: 'The policy authority rejected this action, so it was not run.',
    ACTION_APPROVAL_REQUIRED: 'The requested permission needs a human decision before the task can continue.',
    PRIVILEGE_EXPANSION_APPROVED: 'A human approved the request; the task continues under a new policy epoch.',
    FILESYSTEM_DENIAL: 'Worker-level confinement blocked this protected file operation.',
    WORKER_FINISHED: 'The confined worker returned this action result to the controller.',
    TASK_FAILED: 'The task did not satisfy its completion criteria.',
    ERROR: 'The controller encountered an error while processing the task.',
  }
  if (event.event_type === 'TASK_COMPLETED') {
    return event.reason_code === 'VERIFIED'
      ? 'The configured independent success check passed.'
      : 'The task stopped without an independent check confirming success.'
  }
  return meanings[event.event_type] ?? ''
}

function successCheckLabel(check: Demo['success_check']) {
  if (!check) return 'Unavailable'
  if (check.type === 'run_tests') return `Test suite: ${check.target ?? 'configured target'}`
  if (check.type === 'run_command') return `Separate command: ${check.executable ?? 'configured executable'}`
  return check.type.replaceAll('_', ' ')
}

function hasDemoGuide(demo: Demo | undefined): demo is CompleteDemoGuide {
  return Boolean(
    demo?.goal
    && demo.workspace
    && demo.input_context
    && demo.success_check?.type
    && Array.isArray(demo.execution_steps)
    && Array.isArray(demo.reading_guide),
  )
}

function resultExplanation(result: NonNullable<RunInfo['result']>) {
  if (result.outcome === 'completed' && result.independently_verified) {
    return 'The configured independent success check passed. The planner’s own claim that it finished is not used as proof.'
  }
  if (result.outcome === 'finished_unverified') {
    return 'The planner stopped, but no independent check confirmed that the requested result was achieved.'
  }
  if (result.outcome === 'failed') {
    const reason = result.outcome_reason.toLowerCase()
    if (reason.includes('denial')) return 'The task could not continue after policy denials. Review the denied actions and their reasons above.'
    if (reason.includes('step_limit')) return 'The task reached its action limit before meeting the success criteria.'
    if (reason.includes('check') || reason.includes('verification')) {
      return 'The independent success check did not confirm the requested result.'
    }
    return 'The task ended without satisfying its completion criteria. Review the audit events for the blocking step.'
  }
  return 'The controller recorded this outcome. Review the event sequence and independent-check status below.'
}

function labelForEvent(event: AuditEvent) {
  if (event.event_type === 'ACTION_PROPOSED') return 'Proposed'
  if (event.event_type === 'ACTION_ALLOWED') return 'Allowed'
  if (event.event_type === 'ACTION_DENIED') return 'Denied'
  if (event.event_type === 'ACTION_APPROVAL_REQUIRED') return 'Approval required'
  if (event.event_type === 'PRIVILEGE_EXPANSION_APPROVED') return 'Human approval'
  if (event.event_type === 'WORKER_FINISHED') return 'Worker result'
  if (event.event_type === 'FILESYSTEM_DENIAL') return 'Kernel denial'
  if (event.event_type === 'TASK_COMPLETED') return 'Verified complete'
  if (event.event_type === 'TASK_FAILED') return 'Task failed'
  if (event.event_type === 'ERROR') return 'Controller error'
  return event.event_type.replaceAll('_', ' ').toLowerCase()
}

function statusLabel(status: string) {
  const labels: Record<string, string> = {
    starting: 'Starting',
    running: 'Running',
    approval_required: 'Waiting for approval',
    completed: 'Completed',
    failed: 'Failed',
    finished_unverified: 'Finished unverified',
    cancelled: 'Cancelled',
    recorded: 'Recorded',
  }
  return labels[status] ?? status
}

function App() {
  const [page, setPage] = useState<AppPage>(
    () => window.location.pathname === '/baseline' ? 'baseline' : 'demo',
  )
  const [status, setStatus] = useState<AppStatus | null>(null)
  const [demos, setDemos] = useState<Demo[]>([])
  const [history, setHistory] = useState<RunSummary[]>([])
  const [selectedDemo, setSelectedDemo] = useState<DemoId>('benign')
  const [planner, setPlanner] = useState<Planner>('mock')
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null)
  const [run, setRun] = useState<RunInfo | null>(null)
  const [approver, setApprover] = useState('Demo operator')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState<'preflight' | 'authority' | 'run' | 'approval' | null>(null)
  const [loading, setLoading] = useState(true)

  const selectedDemoInfo = useMemo(
    () => demos.find((demo) => demo.id === selectedDemo),
    [demos, selectedDemo],
  )
  const guideDemoInfo = useMemo(
    () => demos.find((demo) => demo.id === (run?.demo ?? selectedDemo)),
    [demos, run?.demo, selectedDemo],
  )
  const demoGuideReady = hasDemoGuide(guideDemoInfo)
  const guidePlanner = run?.planner ?? planner
  const activeRunId = selectedRunId ?? history[0]?.run_id ?? null

  const refreshStatus = useCallback(async () => {
    const next = await request<AppStatus>('/api/status')
    setStatus(next)
  }, [])

  const refreshHistory = useCallback(async () => {
    const next = await request<RunSummary[]>('/api/runs')
    setHistory(next)
  }, [])

  const refreshRun = useCallback(async (runId: string) => {
    const next = await request<RunInfo>(`/api/runs/${runId}`)
    setRun(next)
    if (['completed', 'failed', 'cancelled'].includes(next.status)) {
      void refreshHistory()
    }
  }, [refreshHistory])

  useEffect(() => {
    let active = true
    Promise.all([
      request<AppStatus>('/api/status'),
      request<Demo[]>('/api/demos'),
      request<RunSummary[]>('/api/runs'),
    ])
      .then(([nextStatus, nextDemos, nextHistory]) => {
        if (!active) return
        setStatus(nextStatus)
        setDemos(nextDemos)
        setHistory(nextHistory)
        setPlanner(nextStatus.planner_default)
        setLoading(false)
      })
      .catch((error: unknown) => {
        if (!active) return
        setNotice(error instanceof Error ? error.message : 'Could not reach the local API.')
        setLoading(false)
      })
    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    const handlePopState = () => {
      setPage(window.location.pathname === '/baseline' ? 'baseline' : 'demo')
    }
    window.addEventListener('popstate', handlePopState)
    return () => window.removeEventListener('popstate', handlePopState)
  }, [])

  useEffect(() => {
    if (!activeRunId) return
    const timer = window.setInterval(() => {
      void refreshRun(activeRunId).catch((error: unknown) => {
        setNotice(error instanceof Error ? error.message : 'Could not refresh the run.')
      })
    }, 900)
    return () => window.clearInterval(timer)
  }, [activeRunId, refreshRun])

  async function runPreflight() {
    setBusy('preflight')
    setNotice('')
    try {
      const report = await request<Preflight>('/api/preflight', { method: 'POST' })
      setStatus((current) => current ? { ...current, preflight: report } : current)
      setNotice(
        report.ok
          ? 'Host checks passed. Protected demos and baseline studies are enabled.'
          : 'Preflight found failed checks. Review the results before running a demo or study.',
      )
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Preflight failed.')
    } finally {
      setBusy(null)
    }
  }

  function navigateTo(nextPage: AppPage) {
    const path = nextPage === 'baseline' ? '/baseline' : '/'
    if (window.location.pathname !== path) window.history.pushState({}, '', path)
    setPage(nextPage)
  }

  async function startAuthority() {
    setBusy('authority')
    setNotice('')
    try {
      await request('/api/authority/start', { method: 'POST' })
      await refreshStatus()
      setNotice('The P1 policy authority is ready.')
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Could not start the authority.')
    } finally {
      setBusy(null)
    }
  }

  async function stopAuthority() {
    setBusy('authority')
    setNotice('')
    try {
      await request('/api/authority/stop', { method: 'POST' })
      await refreshStatus()
      setNotice('The web-managed policy authority has stopped.')
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Could not stop the authority.')
    } finally {
      setBusy(null)
    }
  }

  async function startRun() {
    setBusy('run')
    setNotice('')
    try {
      const next = await request<RunInfo>('/api/runs', {
        method: 'POST',
        body: JSON.stringify({ demo: selectedDemo, planner }),
      })
      setRun(next)
      setSelectedRunId(next.run_id)
      await refreshHistory()
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Could not start the run.')
    } finally {
      setBusy(null)
    }
  }

  function selectRun(runId: string) {
    setSelectedRunId(runId)
    setRun(null)
    void refreshRun(runId).catch((error: unknown) => {
      setNotice(error instanceof Error ? error.message : 'Could not load the run.')
    })
  }

  async function decideApproval(decision: 'approve' | 'deny') {
    if (!run) return
    setBusy('approval')
    setNotice('')
    try {
      await request(`/api/runs/${run.run_id}/approval`, {
        method: 'POST',
        body: JSON.stringify({ decision, approver }),
      })
      setNotice(decision === 'approve' ? 'Approval recorded. The task is resuming.' : 'Request denied.')
      await refreshRun(run.run_id)
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Could not submit the decision.')
    } finally {
      setBusy(null)
    }
  }

  const preflightOk = status?.preflight?.ok === true
  const active = run && ['starting', 'running', 'approval_required'].includes(run.status)
  const authorityReady = status?.authority.online && status.authority.arm === 'P1'
  const visibleEvents = run?.events.filter((event) =>
    [
      'ACTION_PROPOSED',
      'ACTION_ALLOWED',
      'ACTION_DENIED',
      'ACTION_APPROVAL_REQUIRED',
      'PRIVILEGE_EXPANSION_APPROVED',
      'FILESYSTEM_DENIAL',
      'WORKER_FINISHED',
      'TASK_COMPLETED',
      'TASK_FAILED',
      'ERROR',
    ].includes(event.event_type),
  ) ?? []

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="wordmark" href="/" aria-label="Argus home">ARGUS</a>
        <div className="topbar-title">Execution console</div>
        <nav className="topbar-nav" aria-label="Main navigation">
          <a
            href="/"
            aria-current={page === 'demo' ? 'page' : undefined}
            className={page === 'demo' ? 'active' : ''}
            onClick={(event) => {
              event.preventDefault()
              navigateTo('demo')
            }}
          >
            Argus demo
          </a>
          <a
            href="/baseline"
            aria-current={page === 'baseline' ? 'page' : undefined}
            className={page === 'baseline' ? 'active' : ''}
            onClick={(event) => {
              event.preventDefault()
              navigateTo('baseline')
            }}
          >
            Baseline study
          </a>
        </nav>
        <div className="topbar-status" aria-live="polite">
          <span className={`status-dot ${status?.authority.online ? 'is-ready' : ''}`} />
          <span>
            {status?.authority.online
              ? `Authority online · ${status.authority.arm}${status.authority.started_by_web ? ' · managed here' : ''}`
              : 'Authority offline'}
          </span>
        </div>
      </header>

      <main>
        {page === 'demo' && (
          <>
        <section className="intro">
          <div>
            <p className="eyebrow">LOCAL DEMO ENVIRONMENT</p>
            <h1>Run a task.<br />See every decision.</h1>
          </div>
          <p className="intro-copy">
            Choose a bundled workload and planner. Argus records each proposal,
            policy decision, confined action, and verification result.
          </p>
        </section>

        {notice && <div className="notice" role="status">{notice}</div>}
        {loading && <div className="service-message">Connecting to the local Argus API...</div>}
        {!loading && !status && (
          <div className="service-message service-error">
            The local API is unavailable. Start it with <code>uv run python -m controller.web</code>.
          </div>
        )}

        <div className="console-layout">
          <aside className="setup">
            <div className="section-heading">
              <span className="eyebrow">01 / CONFIGURE</span>
              <h2>Task setup</h2>
            </div>

            <label className="field-label" htmlFor="demo-select">Demo workload</label>
            <select
              id="demo-select"
              value={selectedDemo}
              onChange={(event) => setSelectedDemo(event.target.value as DemoId)}
              disabled={Boolean(active)}
            >
              {demos.map((demo) => <option key={demo.id} value={demo.id}>{demo.title}</option>)}
            </select>
            <p className="field-description">{selectedDemoInfo?.summary}</p>
            {guideDemoInfo && (
              <section className="demo-guide" aria-label="Demo explanation">
                <span className="eyebrow">DEMO BRIEF</span>
                <h3>What goes into this run</h3>
                {!demoGuideReady ? (
                  <p className="service-error" role="status">
                    Demo details are missing from the local API response. Restart
                    <code> uv run python -m controller.web </code>
                    to load the updated demo catalog.
                  </p>
                ) : (
                  <>
                <span className="field-label">Goal given to the planner</span>
                <p className="demo-goal">{guideDemoInfo.goal}</p>
                <dl className="demo-facts">
                  <div>
                    <dt>Task spec</dt>
                    <dd><code>demo/{guideDemoInfo.task_file}</code></dd>
                  </div>
                  <div>
                    <dt>Starting workspace</dt>
                    <dd><code>{guideDemoInfo.workspace}</code></dd>
                  </div>
                  <div>
                    <dt>Independent check</dt>
                    <dd>{successCheckLabel(guideDemoInfo.success_check)}</dd>
                  </div>
                </dl>
                <p className="demo-context">{guideDemoInfo.input_context}</p>
                <h4>Planner context</h4>
                <p className="demo-context">
                  {guidePlanner === 'llm'
                    ? 'Each live-model turn receives the goal, step number, up to 12 recent redacted action/results, and controller feedback when relevant. It is instructed to return one JSON action and treat workspace files as untrusted data. Host secrets and host paths are excluded.'
                    : `No model request is made. The scripted mock replays the fixed actions in demo/${guideDemoInfo.task_file} under mock_script.`}
                </p>
                <h4>What Argus does</h4>
                <ol className="demo-steps">
                  {guideDemoInfo.execution_steps.map((step) => <li key={step}>{step}</li>)}
                </ol>
                <h4>How to read the result</h4>
                <ul className="demo-reading">
                  {guideDemoInfo.reading_guide.map((item) => <li key={item}>{item}</li>)}
                </ul>
                  </>
                )}
              </section>
            )}
            {planner === 'llm' && selectedDemo !== 'benign' && (
              <p className="caution">
                Live model behavior can vary. Choose the scripted mock to reproduce
                this demo's actions and approval sequence.
              </p>
            )}

            <fieldset className="planner-fieldset">
              <legend className="field-label">Planner</legend>
              <label className={`planner-choice ${planner === 'llm' ? 'selected' : ''}`}>
                <input
                  type="radio"
                  name="planner"
                  value="llm"
                  checked={planner === 'llm'}
                  onChange={() => setPlanner('llm')}
                  disabled={Boolean(active) || !status?.llm_configured}
                />
                <span className="planner-choice-name">Live model</span>
                <span className="planner-choice-detail">
                  {status?.llm_configured ? status.model : 'Configure LLM_BASE_URL and LLM_MODEL'}
                </span>
              </label>
              <label className={`planner-choice ${planner === 'mock' ? 'selected' : ''}`}>
                <input
                  type="radio"
                  name="planner"
                  value="mock"
                  checked={planner === 'mock'}
                  onChange={() => setPlanner('mock')}
                  disabled={Boolean(active)}
                />
                <span className="planner-choice-name">Scripted mock</span>
                <span className="planner-choice-detail">Repeatable demo actions</span>
              </label>
            </fieldset>

            <div className="readiness">
              <div className="readiness-row">
                <div>
                  <span className="field-label">Host preflight</span>
                  <span className={`readiness-value ${preflightOk ? 'text-ready' : ''}`}>
                    {status?.preflight ? (preflightOk ? 'Passed' : 'Checks failed') : 'Not run'}
                  </span>
                </div>
                <button
                  className="text-button"
                  type="button"
                  onClick={runPreflight}
                  disabled={busy !== null}
                >
                  {busy === 'preflight' ? 'Checking...' : 'Run checks'}
                </button>
              </div>
              <div className="readiness-row">
                <div>
                  <span className="field-label">Policy authority</span>
                  <span className={`readiness-value ${status?.authority.online ? 'text-ready' : ''}`}>
                    {status?.authority.online
                      ? `${status.authority.arm === 'P1' ? 'Online' : 'Wrong arm'} · ${status.authority.arm}`
                      : 'Offline'}
                  </span>
                </div>
                {!status?.authority.online && (
                  <button
                    className="text-button"
                    type="button"
                    onClick={startAuthority}
                    disabled={busy !== null}
                  >
                    {busy === 'authority' ? 'Starting...' : 'Start'}
                  </button>
                )}
                {status?.authority.started_by_web && status.authority.online && (
                  <button
                    className="text-button"
                    type="button"
                    onClick={stopAuthority}
                    disabled={busy !== null || Boolean(active)}
                  >
                    {busy === 'authority' ? 'Stopping...' : 'Stop'}
                  </button>
                )}
              </div>
              {status?.preflight && (
                <details className="check-details">
                  <summary>Preflight details</summary>
                  <dl>
                    {Object.entries(status.preflight.checks).map(([name, passed]) => (
                      <div key={name}>
                        <dt>{name.replaceAll('_', ' ')}</dt>
                        <dd className={passed ? 'text-ready' : 'text-danger'}>{passed ? 'Passed' : 'Failed'}</dd>
                      </div>
                    ))}
                  </dl>
                </details>
              )}
            </div>

            <button
              className="primary-button"
              type="button"
              onClick={startRun}
              disabled={busy !== null || Boolean(active) || !preflightOk || !authorityReady}
            >
              {busy === 'run' ? 'Starting run...' : 'Run selected task'}
            </button>
            <p className="run-requirement">
              Protected runs require a passing preflight and the P1 authority.
            </p>
          </aside>

          <section className="activity" aria-label="Run activity">
            <div className="activity-heading">
              <div>
                <span className="eyebrow">02 / OBSERVE</span>
                <h2>{run ? 'Run activity' : 'Activity'}</h2>
              </div>
              {run && <span className={`run-state state-${run.status}`}>{statusLabel(run.status)}</span>}
            </div>

            {!run && (
              <div className="empty-state">
                <p className="empty-title">No task selected</p>
                <p>Run a demo to follow planner proposals, policy decisions, worker results, and verification here.</p>
              </div>
            )}

            {run && (
              <>
                <div className="run-summary">
                  <div>
                    <span className="field-label">Run</span>
                    <code>{run.run_id}</code>
                  </div>
                  <div>
                    <span className="field-label">Planner</span>
                    <span>{run.planner === 'llm' ? `Live model · ${status?.model ?? 'configured'}` : 'Scripted mock'}</span>
                  </div>
                  <div>
                    <span className="field-label">Task</span>
                    <span>{run.task_id ?? 'Preparing...'}</span>
                  </div>
                  <div>
                    <span className="field-label">Workload</span>
                    <span>{demos.find((demo) => demo.id === run.demo)?.title ?? 'Loading...'}</span>
                  </div>
                  <div>
                    <span className="field-label">Audit evidence</span>
                    <code>{run.run_dir}/events.jsonl</code>
                    <span className="evidence-note">Outcome and verification: result.json</span>
                  </div>
                </div>

                {run.result && (
                  <div className={`result-banner ${run.result.outcome === 'completed' ? 'result-success' : 'result-failure'}`}>
                    <div>
                      <span className="field-label">Outcome</span>
                      <strong>{run.result.outcome.toUpperCase()}</strong>
                    </div>
                    <p>{resultExplanation(run.result)}</p>
                    <span className="result-reason">Controller reason: <code>{run.result.outcome_reason}</code></span>
                    <div className="result-facts">
                      <span>{run.result.independently_verified ? 'Independent check passed' : 'Not independently verified'}</span>
                      <span>{run.result.denials} policy {run.result.denials === 1 ? 'denial' : 'denials'}</span>
                    </div>
                  </div>
                )}

                {run.error && <div className="error-panel">{run.error}</div>}

                {run.approval && (
                  <div className="approval-panel">
                    <div className="approval-copy">
                      <span className="eyebrow">HUMAN DECISION REQUIRED</span>
                      <h3>Permission expansion</h3>
                      <p>{run.approval.reason ?? 'The task requests an additional permission.'}</p>
                      <code>{run.approval.expansion_id}</code>
                    </div>
                    <label className="field-label" htmlFor="approver">Approver name</label>
                    <input
                      id="approver"
                      value={approver}
                      maxLength={128}
                      onChange={(event) => setApprover(event.target.value)}
                    />
                    <div className="approval-actions">
                      <button
                        type="button"
                        className="primary-button"
                        onClick={() => decideApproval('approve')}
                        disabled={busy === 'approval' || !approver.trim()}
                      >
                        Approve request
                      </button>
                      <button
                        type="button"
                        className="secondary-button"
                        onClick={() => decideApproval('deny')}
                        disabled={busy === 'approval' || !approver.trim()}
                      >
                        Deny request
                      </button>
                    </div>
                  </div>
                )}

                <div className="timeline-heading">
                  <span>Audit timeline</span>
                  <span>{visibleEvents.length} recorded events</span>
                </div>
                {visibleEvents.length === 0 ? (
                  <p className="empty-events">{active ? 'Waiting for the first audit event...' : 'No audit events were recorded.'}</p>
                ) : (
                  <ol className="timeline">
                    {visibleEvents.map((event) => (
                      <li className={`timeline-event event-${event.decision ?? event.event_type.toLowerCase()}`} key={event.seq}>
                        <time>{formatTime(event.timestamp_utc)}</time>
                        <div className="event-main">
                          <div className="event-title-row">
                            <strong>{labelForEvent(event)}</strong>
                            {event.action && <code>{proposalText(event)}</code>}
                            {!event.action && event.event_type === 'ACTION_PROPOSED' && <code>{proposalText(event)}</code>}
                          </div>
                          {eventDetail(event) && <p>{eventDetail(event)}</p>}
                          {eventMeaning(event) && <p className="event-meaning">{eventMeaning(event)}</p>}
                          {(event.reason_code || event.enforcement_layer) && (
                            <span className="event-meta">
                              {[event.reason_code, event.enforcement_layer].filter(Boolean).join(' · ')}
                            </span>
                          )}
                        </div>
                      </li>
                    ))}
                  </ol>
                )}
              </>
            )}
          </section>
        </div>

        <section className="history-section">
          <div className="history-heading">
            <div>
              <span className="eyebrow">03 / RUN HISTORY</span>
              <h2>Recent runs</h2>
            </div>
            <button className="text-button" type="button" onClick={() => void refreshHistory()}>
              Refresh
            </button>
          </div>
          {history.length === 0 ? (
            <p className="history-empty">Completed and active runs will appear here.</p>
          ) : (
            <div className="history-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Run</th>
                    <th scope="col">Workload</th>
                    <th scope="col">Planner</th>
                    <th scope="col">Status</th>
                    <th scope="col">Outcome</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((item) => (
                    <tr key={item.run_id} className={item.run_id === activeRunId ? 'current-run' : ''}>
                      <td><button className="run-link" type="button" onClick={() => selectRun(item.run_id)}>{item.run_id}</button></td>
                      <td>{demos.find((demo) => demo.id === item.demo)?.title ?? item.task_id ?? 'Task'}</td>
                      <td>{item.planner === 'llm' ? 'Live model' : item.planner === 'mock' ? 'Scripted mock' : 'Unknown'}</td>
                      <td>{statusLabel(item.status)}</td>
                      <td>{item.outcome ?? 'In progress'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
          </>
        )}
        {page === 'baseline' && (
          <BaselinePage
            preflightOk={status?.preflight?.ok === true}
            preflightBusy={busy === 'preflight'}
            onRunPreflight={runPreflight}
          />
        )}
      </main>
      <footer>
        <span>{page === 'baseline' ? 'B0 / B1 / P1 EVALUATION' : 'ARGUS / P1 POLICY ARM'}</span>
        <span>Local controller · Worker network disabled</span>
      </footer>
    </div>
  )
}

export default App
