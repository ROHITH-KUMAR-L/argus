import { useEffect, useState } from 'react'

type StudyArmId = 'B0' | 'B1' | 'P1'

interface StudyRate {
  numerator: number
  denominator: number
  rate: number | null
  ci95: [number, number] | null
}

interface BaselineStudy {
  batch: string
  mode: string
  fresh: boolean
  environment: {
    kernel: string | null
    docker: string | null
    image_tag: string | null
    image_id: string | null
  }
  runs: { scheduled: number; scored: number; invalid: number }
  repetitions: number
  arms: Record<StudyArmId, {
    name: string
    description: string
    attack_success_rate: StudyRate
    attack_success_by_category: Record<string, StudyRate>
    legit_task_completion_rate: StudyRate
    false_denial_rate: StudyRate
  }>
  scenarios: Array<{
    id: string
    category: string
    outcome_type: 'effect' | 'verified' | 'request'
    arms: Record<StudyArmId, { successes: number; scored: number }>
  }>
  limitations: string[]
}

interface BaselineStudyRun {
  study_id?: string
  mode?: 'representative' | 'full'
  status: 'idle' | 'starting' | 'running' | 'completed' | 'failed'
  completed?: number
  total?: number
  current?: {
    scenario_id: string
    arm: StudyArmId
    rep: number
    status: string
    outcome: string
  } | null
  error?: string | null
  output_dir?: string
  result?: BaselineStudy
}

interface BaselinePageProps {
  preflightOk: boolean
  preflightBusy: boolean
  onRunPreflight: () => void
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

function formatRate(rate: StudyRate) {
  const percent = rate.rate === null ? 'n/a' : `${(rate.rate * 100).toFixed(0)}%`
  const interval = rate.ci95
    ? ` · 95% CI ${(rate.ci95[0] * 100).toFixed(0)}-${(rate.ci95[1] * 100).toFixed(0)}%`
    : ''
  return `${percent} (${rate.numerator}/${rate.denominator})${interval}`
}

function outcomeLabel(type: BaselineStudy['scenarios'][number]['outcome_type']) {
  if (type === 'effect') return 'Unauthorized effect'
  if (type === 'request') return 'Permission request'
  return 'Verified task'
}

function outcomeCount(
  type: BaselineStudy['scenarios'][number]['outcome_type'],
  outcome: { successes: number; scored: number },
) {
  if (type === 'effect') return `${outcome.successes}/${outcome.scored} effects`
  if (type === 'request') return `${outcome.successes}/${outcome.scored} requests`
  return `${outcome.successes}/${outcome.scored} passed`
}

export default function BaselinePage({
  preflightOk,
  preflightBusy,
  onRunPreflight,
}: BaselinePageProps) {
  const [study, setStudy] = useState<BaselineStudy | null>(null)
  const [studyRun, setStudyRun] = useState<BaselineStudyRun | null>(null)
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    void request<BaselineStudy>('/api/studies/baseline')
      .then((result) => {
        if (active) setStudy(result)
      })
      .catch((cause: unknown) => {
        if (active) setError(cause instanceof Error ? cause.message : 'Could not load stored results.')
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    void request<BaselineStudyRun>('/api/studies/baseline/status')
      .then((result) => {
        if (!active || result.status === 'idle') return
        setStudyRun(result)
        if (result.result) setStudy(result.result)
      })
      .catch((cause: unknown) => {
        if (active) setError(cause instanceof Error ? cause.message : 'Could not load study status.')
      })
    return () => {
      active = false
    }
  }, [])

  const studyStatus = studyRun?.status

  useEffect(() => {
    if (!studyStatus || !['starting', 'running'].includes(studyStatus)) return
    let active = true
    const poll = async () => {
      try {
        const next = await request<BaselineStudyRun>('/api/studies/baseline/status')
        if (!active) return
        setStudyRun(next)
        setError('')
        if (next.result) setStudy(next.result)
      } catch (cause) {
        if (active) setError(cause instanceof Error ? cause.message : 'Could not refresh study progress.')
      }
    }
    const timer = window.setInterval(() => void poll(), 1200)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [studyStatus])

  async function startStudy(mode: 'representative' | 'full') {
    setStarting(true)
    setError('')
    try {
      const next = await request<BaselineStudyRun>('/api/studies/baseline', {
        method: 'POST',
        body: JSON.stringify({ mode }),
      })
      setStudyRun(next)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not start the baseline study.')
    } finally {
      setStarting(false)
    }
  }

  const studyActive = studyRun && ['starting', 'running'].includes(studyRun.status)

  return (
    <>
      <section className="intro">
        <div>
          <p className="eyebrow">CONTROLLED B0 / B1 / P1 EVALUATION</p>
          <h1>Run the baseline.<br />Compare the controls.</h1>
        </div>
        <p className="intro-copy">
          Execute the repository evaluation harness from the browser, follow progress,
          and inspect the measured outcomes for all three arms.
        </p>
      </section>

      <section className="study-section baseline-page" aria-labelledby="study-title">
        <div className="history-heading">
          <div>
            <span className="eyebrow">01 / RUN A COMPARISON</span>
            <h2 id="study-title">Baseline study</h2>
          </div>
        </div>

        <div className="study-disclaimer">
          <strong>B0 is an isolated, ungated baseline, not an unconfined host run.</strong>
          <p>
            It removes Argus task-level policy and project confinement while retaining the
            same disposable Docker worker, Docker outer protections, and disabled networking.
            No arbitrary command, workspace, target, or host path can be entered here.
          </p>
        </div>

        <div className="study-controls">
          <div>
            <span className="field-label">Host preflight</span>
            <span className={`readiness-value ${preflightOk ? 'text-ready' : ''}`}>
              {preflightOk ? 'Passed' : 'Required before running'}
            </span>
          </div>
          {!preflightOk && (
            <button
              className="text-button"
              type="button"
              onClick={onRunPreflight}
              disabled={preflightBusy || starting || Boolean(studyActive)}
            >
              {preflightBusy ? 'Checking...' : 'Run host checks'}
            </button>
          )}
        </div>

        <p className="study-key">
          Both options run the same fixed scenario set across B0, B1, and P1 using the
          deterministic scripted planner. The full study uses three repetitions and writes a
          complete evidence batch.
        </p>
        <div className="study-actions">
          <button
            className="secondary-button"
            type="button"
            onClick={() => void startStudy('representative')}
            disabled={!preflightOk || starting || Boolean(studyActive)}
          >
            Run representative comparison (9 runs)
          </button>
          <button
            className="primary-button"
            type="button"
            onClick={() => void startStudy('full')}
            disabled={!preflightOk || starting || Boolean(studyActive)}
          >
            Run full study (153 runs)
          </button>
        </div>

        {studyActive && (
          <div className="study-progress" role="status" aria-live="polite">
            <div className="study-progress-heading">
              <strong>{studyRun.status === 'starting' ? 'Preparing study workers' : 'Study in progress'}</strong>
              <span>{studyRun.completed ?? 0} / {studyRun.total ?? 0} runs</span>
            </div>
            <progress
              max={studyRun.total || 1}
              value={studyRun.completed ?? 0}
              aria-label="Baseline study progress"
            />
            {studyRun.current && (
              <p>
                Latest: {studyRun.current.scenario_id} · {studyRun.current.arm}
                {' · '}repetition {studyRun.current.rep}
                {' · '}{studyRun.current.outcome}
              </p>
            )}
            <p className="study-run-note">
              Keep this API process running until the study completes. Results are saved under
              <code> {studyRun.output_dir}</code>.
            </p>
          </div>
        )}

        {studyRun?.status === 'completed' && (
          <p className="study-message text-ready" role="status">
            Fresh comparison complete. Results below are from <code>{studyRun.study_id}</code>.
          </p>
        )}
        {studyRun?.status === 'failed' && (
          <p className="study-message service-error" role="alert">
            Study failed: {studyRun.error ?? 'Check the API terminal for details.'}
            {studyRun.output_dir && <> Partial evidence may be in <code>{studyRun.output_dir}</code>.</>}
          </p>
        )}
        {error && <p className="study-message service-error" role="alert">{error}</p>}

        {loading && !study && <p className="study-message">Loading the most recent saved results...</p>}
        {!study && !loading && !error && (
          <p className="study-message">No completed result batch is available yet. Run a comparison above.</p>
        )}
        {study && (
          <>
            <div className="study-summary">
              <p>
                {study.fresh ? 'Fresh results from the evaluation harness.' : 'Previously recorded evaluation results.'}
                {' '}The study compares the same scripted scenarios, fixtures, and disposable Docker workers.
              </p>
              <span>
                {study.batch} · {study.runs.scored}/{study.runs.scheduled} scored
                · {study.repetitions} repetitions
              </span>
            </div>

            <div className="study-table-wrap">
              <table className="study-table">
                <thead>
                  <tr>
                    <th scope="col">Execution arm</th>
                    <th scope="col">Attack effects</th>
                    <th scope="col">Legitimate completion (step-up shown separately)</th>
                    <th scope="col">False denials</th>
                  </tr>
                </thead>
                <tbody>
                  {(['B0', 'B1', 'P1'] as const).map((arm) => (
                    <tr key={arm}>
                      <th scope="row">
                        <strong>{arm}</strong>
                        <span>{study.arms[arm].name}</span>
                        <small>{study.arms[arm].description}</small>
                      </th>
                      <td>{formatRate(study.arms[arm].attack_success_rate)}</td>
                      <td>{formatRate(study.arms[arm].legit_task_completion_rate)}</td>
                      <td>{formatRate(study.arms[arm].false_denial_rate)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <h3 className="study-subheading">Attack outcomes by category</h3>
            <div className="study-table-wrap">
              <table className="study-table study-category-table">
                <thead>
                  <tr>
                    <th scope="col">Scenario category</th>
                    <th scope="col">B0</th>
                    <th scope="col">B1</th>
                    <th scope="col">P1</th>
                  </tr>
                </thead>
                <tbody>
                  {['prompt_injection', 'staged_escalation', 'subprocess_misuse'].map((category) => (
                    <tr key={category}>
                      <th scope="row">{category.replaceAll('_', ' ')}</th>
                      {(['B0', 'B1', 'P1'] as const).map((arm) => {
                        const rate = study.arms[arm].attack_success_by_category[category]
                        return <td key={arm}>{rate ? formatRate(rate) : 'n/a'}</td>
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <h3 className="study-subheading">Per-scenario comparison</h3>
            <p className="study-key">
              Effects are unauthorized attack outcomes. Verified task rows measure legitimate
              success; the step-up scenario measures whether a permission request was made.
            </p>
            <div className="study-table-wrap">
              <table className="study-table scenario-table">
                <thead>
                  <tr>
                    <th scope="col">Scenario</th>
                    <th scope="col">Category / measure</th>
                    <th scope="col">B0</th>
                    <th scope="col">B1</th>
                    <th scope="col">P1</th>
                  </tr>
                </thead>
                <tbody>
                  {study.scenarios.map((scenario) => (
                    <tr key={scenario.id}>
                      <th scope="row">{scenario.id}</th>
                      <td>{scenario.category.replaceAll('_', ' ')} · {outcomeLabel(scenario.outcome_type)}</td>
                      {(['B0', 'B1', 'P1'] as const).map((arm) => (
                        <td key={arm}>{outcomeCount(scenario.outcome_type, scenario.arms[arm])}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <details className="study-provenance">
              <summary>Method, environment, and limitations</summary>
              <dl>
                <div><dt>Kernel</dt><dd>{study.environment.kernel ?? 'Not recorded'}</dd></div>
                <div><dt>Docker</dt><dd>{study.environment.docker ?? 'Not recorded'}</dd></div>
                <div><dt>Worker image</dt><dd>{study.environment.image_tag ?? 'Not recorded'} · {study.environment.image_id ?? 'digest not recorded'}</dd></div>
                <div><dt>Invalid runs</dt><dd>{study.runs.invalid}</dd></div>
              </dl>
              <ul>
                {study.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
              </ul>
              <p>
                Source files: <code>evaluation/results/{study.batch}/</code>
                {study.fresh && <>; fresh output: <code>{study.batch}</code> under the runs directory</>}.
              </p>
            </details>
          </>
        )}
      </section>
    </>
  )
}
