import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Archive, Building2, Cloud, LoaderCircle, Plus, RefreshCw, ShieldCheck, Pencil, X, BadgeCheck, Copy, Check } from 'lucide-react';
import { apiClient, type APIResponse } from '../api/client';

interface CloudProject {
  project_id: string;
  name: string;
  description: string;
  account_id: string | null;
  role_arn: string | null;
  external_id: string | null;
  verification_status: 'NOT_CHECKED' | 'CONNECTED' | 'FAILED';
  verified_at: string | null;
  verified_account_id: string | null;
  verification_error: string | null;
  connected?: boolean;
  status: string;
  created_at: string;
  updated_at: string;
}

const fetchProjects = async (): Promise<CloudProject[]> => {
  const response = await apiClient.get<APIResponse<CloudProject[]>>('/projects');
  return response.data.data;
};

export const Projects: React.FC = () => {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [accountId, setAccountId] = useState('');
  const [roleArn, setRoleArn] = useState('');
  const [description, setDescription] = useState('');
  const [formError, setFormError] = useState('');
  const [editingProjectId, setEditingProjectId] = useState<string | null>(null);
  const [copiedExternalId, setCopiedExternalId] = useState<string | null>(null);
  const projects = useQuery({ queryKey: ['projects'], queryFn: fetchProjects });
  const resetForm = () => {
    setName(''); setAccountId(''); setRoleArn(''); setDescription(''); setFormError(''); setEditingProjectId(null);
  };
  const createProject = useMutation({
    mutationFn: async () => {
      const response = await apiClient.post<APIResponse<CloudProject>>('/projects', {
        name, description, account_id: accountId || null, role_arn: roleArn || null,
      });
      return response.data.data;
    },
    onSuccess: async () => {
      resetForm();
      await queryClient.invalidateQueries({ queryKey: ['projects'] });
    },
    onError: (error: any) => setFormError(error?.response?.data?.detail || 'Could not create project.'),
  });
  const updateProject = useMutation({
    mutationFn: async () => {
      if (!editingProjectId) throw new Error('Choose a project to edit.');
      const response = await apiClient.patch<APIResponse<CloudProject>>(`/projects/${editingProjectId}`, {
        name, description, account_id: accountId || null, role_arn: roleArn || null,
      });
      return response.data.data;
    },
    onSuccess: async () => {
      resetForm();
      await queryClient.invalidateQueries({ queryKey: ['projects'] });
    },
    onError: (error: any) => setFormError(error?.response?.data?.detail || error?.message || 'Could not update project.'),
  });
  const archiveProject = useMutation({
    mutationFn: (projectId: string) => apiClient.delete(`/projects/${projectId}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['projects'] }),
    onError: (error: any) => setFormError(error?.response?.data?.detail || 'Could not archive project.'),
  });
  const verifyProject = useMutation({
    mutationFn: async (projectId: string) => {
      const response = await apiClient.post<APIResponse<CloudProject>>(`/projects/${projectId}/verify`);
      return response.data.data;
    },
    onSuccess: async (project) => {
      if (!project.connected) setFormError(project.verification_error || 'AWS role verification failed.');
      await queryClient.invalidateQueries({ queryKey: ['projects'] });
    },
    onError: (error: any) => setFormError(error?.response?.data?.detail || 'Could not verify this AWS role.'),
  });

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    setFormError('');
    if (editingProjectId) updateProject.mutate();
    else createProject.mutate();
  };

  const beginEdit = (project: CloudProject) => {
    setEditingProjectId(project.project_id);
    setName(project.name);
    setAccountId(project.account_id || '');
    setRoleArn(project.role_arn || '');
    setDescription(project.description || '');
    setFormError('');
  };

  const copyExternalId = async (project: CloudProject) => {
    if (!project.external_id) return;
    try {
      await navigator.clipboard.writeText(project.external_id);
      setCopiedExternalId(project.project_id);
      window.setTimeout(() => setCopiedExternalId(null), 1800);
    } catch {
      setFormError('Clipboard access is unavailable. Select and copy the External ID manually.');
    }
  };

  return (
    <div className="mx-auto flex-1 min-h-0 w-full max-w-[1440px] overflow-y-auto bg-enterprise-bg p-4 sm:p-6 lg:p-8 space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-enterprise-accent"><Building2 className="h-5 w-5" /><span className="text-xs font-semibold uppercase tracking-wider">CloudScope</span></div>
          <h1 className="mt-2 text-2xl font-bold text-enterprise-text">AWS account projects</h1>
          <p className="mt-1 max-w-2xl text-sm text-enterprise-subtext">Group your cloud security work by AWS account. Account role details are stored per project and kept separate between signed-in owners.</p>
        </div>
        <button onClick={() => projects.refetch()} className="inline-flex items-center gap-2 rounded-lg border border-enterprise-border px-3 py-2 text-sm text-enterprise-text hover:bg-enterprise-card" aria-label="Refresh projects">
          <RefreshCw className={`h-4 w-4 ${projects.isFetching ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </header>

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1.3fr)_minmax(320px,0.7fr)]">
        <div className="space-y-3">
          <div className="flex items-center justify-between"><h2 className="text-sm font-semibold text-enterprise-text">Registered accounts</h2><span className="text-xs text-enterprise-subtext">{projects.data?.length ?? 0} projects</span></div>
          {projects.isLoading && <div className="flex items-center gap-2 rounded-xl border border-enterprise-border bg-enterprise-card p-6 text-sm text-enterprise-subtext"><LoaderCircle className="h-4 w-4 animate-spin" />Loading projects…</div>}
          {projects.isError && <div role="alert" className="rounded-xl border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-500">Unable to load projects. Check the backend connection and retry.</div>}
          {projects.isSuccess && projects.data.length === 0 && <div className="rounded-xl border border-dashed border-enterprise-border bg-enterprise-card/60 p-8 text-center"><Cloud className="mx-auto h-8 w-8 text-enterprise-subtext" /><h3 className="mt-3 font-semibold text-enterprise-text">No AWS accounts yet</h3><p className="mt-1 text-sm text-enterprise-subtext">Create a project to register an AWS account and keep its access configuration organized.</p></div>}
          <div className="space-y-3">
            {projects.data?.map((project) => (
              <article key={project.project_id} className="rounded-xl border border-enterprise-border bg-enterprise-card p-5">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex min-w-0 items-start gap-3"><div className="rounded-lg bg-enterprise-accent/10 p-2 text-enterprise-accent"><Cloud className="h-5 w-5" /></div><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><h3 className="truncate font-semibold text-enterprise-text">{project.name}</h3><span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${project.verification_status === 'CONNECTED' ? 'bg-emerald-500/10 text-emerald-500' : project.verification_status === 'FAILED' ? 'bg-red-500/10 text-red-500' : 'bg-amber-500/10 text-amber-500'}`}>{project.verification_status === 'CONNECTED' ? 'Connected' : project.verification_status === 'FAILED' ? 'Check failed' : 'Not verified'}</span></div><p className="mt-1 text-sm text-enterprise-subtext">{project.description || 'No description'}</p></div></div>
                  <div className="flex shrink-0 gap-1">
                    <button onClick={() => beginEdit(project)} title={`Edit ${project.name}`} className="rounded-md p-2 text-enterprise-subtext hover:bg-enterprise-accent/10 hover:text-enterprise-accent"><Pencil className="h-4 w-4" /></button>
                    <button onClick={() => archiveProject.mutate(project.project_id)} disabled={archiveProject.isPending} title={`Archive ${project.name}`} className="rounded-md p-2 text-enterprise-subtext hover:bg-red-500/10 hover:text-red-500 disabled:opacity-50"><Archive className="h-4 w-4" /></button>
                  </div>
                </div>
                <div className="mt-4 grid gap-3 border-t border-enterprise-border pt-4 sm:grid-cols-2">
                  <div><p className="text-[11px] uppercase tracking-wide text-enterprise-subtext">AWS account ID</p><p className="mt-1 font-mono text-sm text-enterprise-text">{project.account_id || 'Not configured'}</p></div>
                  <div><p className="text-[11px] uppercase tracking-wide text-enterprise-subtext">Read role</p><p className="mt-1 truncate font-mono text-xs text-enterprise-text" title={project.role_arn || undefined}>{project.role_arn || 'Not configured'}</p></div>
                </div>
                {project.role_arn && project.external_id && <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-lg bg-enterprise-bg p-3"><div className="min-w-0"><p className="text-[10px] uppercase tracking-wide text-enterprise-subtext">External ID for role trust policy</p><p className="mt-1 truncate font-mono text-xs text-enterprise-text">{project.external_id}</p></div><button onClick={() => copyExternalId(project)} className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-enterprise-border px-2.5 py-1.5 text-xs text-enterprise-text hover:bg-enterprise-card" aria-label="Copy External ID">{copiedExternalId === project.project_id ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}{copiedExternalId === project.project_id ? 'Copied' : 'Copy'}</button></div>}
                {project.verification_error && <p className="mt-3 text-xs text-red-500">{project.verification_error}</p>}
                <div className="mt-3 flex flex-wrap items-center justify-between gap-2"><p className="flex items-center gap-2 text-xs text-enterprise-subtext"><ShieldCheck className="h-4 w-4" />{project.verification_status === 'CONNECTED' ? `Verified account ${project.verified_account_id}` : 'Verify access before using this account.'}</p><button onClick={() => verifyProject.mutate(project.project_id)} disabled={!project.role_arn || verifyProject.isPending} className="inline-flex items-center gap-1.5 rounded-lg border border-enterprise-border px-3 py-1.5 text-xs font-medium text-enterprise-text hover:bg-enterprise-bg disabled:cursor-not-allowed disabled:opacity-50">{verifyProject.isPending && verifyProject.variables === project.project_id ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <BadgeCheck className="h-3.5 w-3.5" />}{!project.role_arn ? 'Add role to verify' : verifyProject.isPending && verifyProject.variables === project.project_id ? 'Verifying…' : 'Verify access'}</button></div>
              </article>
            ))}
          </div>
        </div>

        <form onSubmit={submit} className="h-fit space-y-4 rounded-xl border border-enterprise-border bg-enterprise-card p-5">
          <div className="flex items-start justify-between gap-2"><div><h2 className="font-semibold text-enterprise-text">{editingProjectId ? 'Edit AWS account' : 'Add an AWS account'}</h2><p className="mt-1 text-xs text-enterprise-subtext">Use an IAM role with read-only security inventory permissions.</p></div>{editingProjectId && <button type="button" onClick={resetForm} aria-label="Cancel editing" className="rounded-md p-1.5 text-enterprise-subtext hover:bg-enterprise-bg"><X className="h-4 w-4" /></button>}</div>
          <label className="block text-xs font-medium text-enterprise-text">Project name <span className="text-red-500">*</span><input required minLength={2} maxLength={120} value={name} onChange={(e) => setName(e.target.value)} placeholder="Production account" className="mt-1.5 w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2.5 text-sm text-enterprise-text outline-none focus:border-enterprise-accent" /></label>
          <label className="block text-xs font-medium text-enterprise-text">AWS account ID<input inputMode="numeric" pattern="[0-9]{12}" maxLength={12} value={accountId} onChange={(e) => setAccountId(e.target.value.replace(/\D/g, '').slice(0, 12))} placeholder="123456789012" className="mt-1.5 w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2.5 font-mono text-sm text-enterprise-text outline-none focus:border-enterprise-accent" /></label>
          <label className="block text-xs font-medium text-enterprise-text">IAM role ARN<input value={roleArn} onChange={(e) => setRoleArn(e.target.value)} placeholder="arn:aws:iam::123456789012:role/CloudScopeReadOnly" className="mt-1.5 w-full rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2.5 font-mono text-xs text-enterprise-text outline-none focus:border-enterprise-accent" /></label>
          <label className="block text-xs font-medium text-enterprise-text">Description <span className="font-normal text-enterprise-subtext">(optional)</span><textarea maxLength={2000} rows={3} value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What does this account host?" className="mt-1.5 w-full resize-y rounded-lg border border-enterprise-border bg-enterprise-bg px-3 py-2.5 text-sm text-enterprise-text outline-none focus:border-enterprise-accent" /></label>
          {formError && <p role="alert" className="rounded-lg bg-red-500/10 px-3 py-2 text-xs text-red-500">{formError}</p>}
          <button type="submit" disabled={createProject.isPending || updateProject.isPending || !name.trim()} className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-enterprise-accent px-4 py-2.5 text-sm font-semibold text-white hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50">{editingProjectId ? <Pencil className="h-4 w-4" /> : <Plus className="h-4 w-4" />}{updateProject.isPending ? 'Saving…' : editingProjectId ? 'Save changes' : createProject.isPending ? 'Adding account…' : 'Add project'}</button>
        </form>
      </section>
    </div>
  );
};
