import { Link } from 'react-router-dom';
import { ArrowRight, Gauge, ShieldAlert, ShieldCheck } from 'lucide-react';
import { ScannedRegionBadge } from '../components/ScannedRegionBadge';

const postureCategories = [
  { name: 'IAM security', weight: '30%', detail: 'Starts at 100 and subtracts the average evidence-based risk score of collected IAM users and roles.' },
  { name: 'Resource security', weight: '25%', detail: 'Starts at 100 and subtracts the average risk score of collected cloud resources, including compute, storage, databases, containers, queues, keys, and workflows.' },
  { name: 'Attack-path risk', weight: '25%', detail: 'Starts at 100 and subtracts 2 points per modeled path, plus 15 per critical path and 8 per high path. The result cannot fall below 0.' },
  { name: 'Identity hygiene', weight: '10%', detail: 'Combines MFA coverage (70% of this category) and whether collected user credentials have been used (30%).' },
  { name: 'Monitoring coverage', weight: '10%', detail: 'Currently scores 0 because the scan does not yet verify complete CloudTrail trail coverage. Events alone do not prove coverage.' },
];

const riskExamples = [
  ['No MFA on an IAM user', '+15 risk points'],
  ['Broad wildcard resource scope', '+25 risk points'],
  ['Unconditional full administrator policy', '+30 risk points'],
  ['Public S3 exposure', '+30 risk points'],
  ['Unencrypted storage', '+15 risk points'],
];

export const ScoringGuide: React.FC = () => (
  <div className="h-full overflow-y-auto bg-enterprise-bg p-6">
    <div className="mx-auto max-w-5xl space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold text-white"><Gauge className="h-6 w-6 text-enterprise-accent" />How CloudScope scoring works</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-enterprise-subtext">Scores are calculated from evidence in the selected published scan. A new scan or snapshot can change the evidence and therefore the displayed scores.</p>
        </div>
        <ScannedRegionBadge />
      </header>

      <section className="rounded-xl border border-enterprise-border bg-enterprise-card p-5">
        <h2 className="flex items-center gap-2 text-base font-bold text-white"><ShieldCheck className="h-5 w-5 text-emerald-400" />Security posture · 0–100</h2>
        <p className="mt-2 text-sm leading-6 text-enterprise-subtext">Higher is better. CloudScope multiplies each category score by its weight and adds the results. Each category is bounded from 0 to 100. Missing evidence is treated conservatively and is identified as unverified in the scan data.</p>
        <div className="mt-4 divide-y divide-enterprise-border">
          {postureCategories.map((category) => <div key={category.name} className="grid gap-1 py-3 sm:grid-cols-[1fr_auto] sm:gap-5"><div><p className="text-sm font-semibold text-white">{category.name}</p><p className="mt-1 text-xs leading-5 text-enterprise-subtext">{category.detail}</p></div><span className="text-sm font-bold text-enterprise-accent">{category.weight}</span></div>)}
        </div>
        <p className="mt-3 rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-xs leading-5 text-blue-100">Scope note: service resources and paths follow the selected scan region(s). IAM users, groups, roles, policies, and their attachments are account-level AWS configuration, so they remain account-wide in a regional scan.</p>
      </section>

      <section className="grid gap-5 lg:grid-cols-2">
        <div className="rounded-xl border border-enterprise-border bg-enterprise-card p-5">
          <h2 className="flex items-center gap-2 text-base font-bold text-white"><ShieldAlert className="h-5 w-5 text-amber-400" />Entity and policy risk · 0–100</h2>
          <p className="mt-2 text-sm leading-6 text-enterprise-subtext">For these risk scores, lower is better. Evidence factors add risk points and the final score is capped at 100. The score describes detected configuration risk; it is not proof of compromise.</p>
          <div className="mt-4 space-y-2">{riskExamples.map(([name, points]) => <div key={name} className="flex items-center justify-between gap-3 rounded-lg bg-enterprise-bg px-3 py-2 text-xs"><span className="text-gray-200">{name}</span><span className="shrink-0 font-semibold text-amber-300">{points}</span></div>)}</div>
          <p className="mt-3 text-xs text-enterprise-subtext">Repeated evidence factors can add together, subject to the 100-point cap. Policy and trust rules that CloudScope does not support may not be represented in the score.</p>
        </div>
        <div className="rounded-xl border border-enterprise-border bg-enterprise-card p-5">
          <h2 className="text-base font-bold text-white">Finding severity bands</h2>
          <p className="mt-2 text-sm leading-6 text-enterprise-subtext">Severity is derived from an individual finding’s score. These bands are separate from the overall security posture score.</p>
          <div className="mt-4 space-y-2">{[['Critical', '80–100'], ['High', '60–79'], ['Medium', '40–59'], ['Low', '0–39']].map(([label, range]) => <div key={label} className="flex items-center justify-between rounded-lg bg-enterprise-bg px-3 py-2 text-sm"><span className="font-semibold text-white">{label}</span><span className="font-mono text-enterprise-subtext">{range}</span></div>)}</div>
          <p className="mt-3 text-xs leading-5 text-enterprise-subtext">The dashboard breakdown counts open canonical findings in the active scan snapshot. Attack paths are shown in the Attack Paths view and are not duplicated as dashboard findings.</p>
        </div>
      </section>

      <Link to="/reports" className="inline-flex items-center gap-2 text-sm font-semibold text-enterprise-accent hover:underline">Open the assessment summary <ArrowRight className="h-4 w-4" /></Link>
    </div>
  </div>
);
