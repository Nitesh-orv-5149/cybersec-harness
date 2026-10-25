// Find infrastructure-as-code files Checkov can check. Done by the workbench before Checkov runs, so a project
// with no IaC is reported as "not applicable" (with what was looked for) instead of as a clean scan, and Checkov
// is only asked to run the frameworks that actually have files.
import fs from 'node:fs';
import path from 'node:path';

export type IacFramework =
  | 'terraform' | 'terraform_json' | 'cloudformation' | 'kubernetes' | 'helm' | 'kustomize' | 'dockerfile'
  | 'github_actions' | 'gitlab_ci' | 'bitbucket_pipelines' | 'azure_pipelines' | 'circleci_pipelines'
  | 'serverless' | 'arm' | 'bicep';

export const FRAMEWORK_LABEL: Record<IacFramework, string> = {
  terraform: 'Terraform', terraform_json: 'Terraform JSON', cloudformation: 'CloudFormation', kubernetes: 'Kubernetes manifests',
  helm: 'Helm charts', kustomize: 'Kustomize', dockerfile: 'Dockerfiles', github_actions: 'GitHub Actions workflows',
  gitlab_ci: 'GitLab CI', bitbucket_pipelines: 'Bitbucket Pipelines', azure_pipelines: 'Azure Pipelines',
  circleci_pipelines: 'CircleCI', serverless: 'Serverless Framework', arm: 'Azure ARM templates', bicep: 'Bicep',
};

export interface IacDetection {
  frameworks: Partial<Record<IacFramework, string[]>>;   // framework -> project-relative files
  filesWalked: number;
  truncated: boolean;
  /** What was looked for, shown when nothing was found. */
  lookedFor: string[];
}

const MAX_FILES = 50_000;
const MAX_SNIFF_BYTES = 512 * 1024;

const sniff = (abs: string): string | null => {
  try { const st = fs.statSync(abs); if (st.size > MAX_SNIFF_BYTES) return null; return fs.readFileSync(abs, 'utf8'); } catch { return null; }
};

function classifyYamlOrJson(rel: string, text: string): IacFramework | null {
  if (/AWSTemplateFormatVersion/.test(text) || /(^|\n)\s*"?Type"?\s*:\s*"?AWS::[A-Za-z0-9]+::/.test(text)) return 'cloudformation';
  if (rel.endsWith('.json') && /"\$schema"\s*:\s*"[^"]*deploymentTemplate\.json/i.test(text)) return 'arm';
  if (/(^|\n)apiVersion\s*:\s*\S+/.test(text) && /(^|\n)kind\s*:\s*[A-Z]\w+/.test(text)) return 'kubernetes';
  return null;
}

export function detectIac(root: string, exclude: string[]): IacDetection {
  const frameworks: IacDetection['frameworks'] = {};
  const add = (fw: IacFramework, rel: string) => { (frameworks[fw] ??= []).push(rel); };
  const skip = new Set(exclude);
  let filesWalked = 0;
  let truncated = false;
  const helmRoots: string[] = [];

  const walk = (dir: string) => {
    if (truncated) return;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (truncated) return;
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) { if (!skip.has(e.name) && e.name !== '.git') walk(abs); continue; }
      if (!e.isFile()) continue;
      if (++filesWalked > MAX_FILES) { truncated = true; return; }
      const rel = path.relative(root, abs).split(path.sep).join('/');
      const base = e.name;
      const lower = base.toLowerCase();
      if (lower.endsWith('.tf.json')) { add('terraform_json', rel); continue; }
      if (lower.endsWith('.tf')) { add('terraform', rel); continue; }
      if (lower.endsWith('.bicep')) { add('bicep', rel); continue; }
      if (base === 'Dockerfile' || base === 'Containerfile' || /^Dockerfile\.[\w.-]+$/.test(base) || lower.endsWith('.dockerfile')) { add('dockerfile', rel); continue; }
      if (base === 'Chart.yaml') { add('helm', rel); helmRoots.push(path.posix.dirname(rel)); continue; }
      if (/^kustomization\.ya?ml$/.test(base)) { add('kustomize', rel); continue; }
      if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(rel)) { add('github_actions', rel); continue; }
      if (base === '.gitlab-ci.yml') { add('gitlab_ci', rel); continue; }
      if (base === 'bitbucket-pipelines.yml') { add('bitbucket_pipelines', rel); continue; }
      if (/^azure-pipelines\.ya?ml$/.test(base)) { add('azure_pipelines', rel); continue; }
      if (/(^|\/)\.circleci\/config\.ya?ml$/.test(rel)) { add('circleci_pipelines', rel); continue; }
      if (/^serverless\.ya?ml$/.test(base)) { add('serverless', rel); continue; }
      if (/\.(ya?ml|json)$/i.test(base) && !/(^|\/)(package(-lock)?|tsconfig|composer)\.json$/.test(rel)) {
        const text = sniff(abs);
        const fw = text ? classifyYamlOrJson(rel, text) : null;
        if (fw) add(fw, rel);
      }
    }
  };
  walk(root);

  // Templates inside a Helm chart are Go templates, not plain manifests; Checkov renders them through the helm framework.
  if (frameworks.kubernetes && helmRoots.length) {
    frameworks.kubernetes = frameworks.kubernetes.filter((f) => !helmRoots.some((h) => f.startsWith(`${h === '.' ? '' : `${h}/`}templates/`)));
    if (!frameworks.kubernetes.length) delete frameworks.kubernetes;
  }
  for (const k of Object.keys(frameworks) as IacFramework[]) frameworks[k]!.sort();
  return { frameworks, filesWalked: Math.min(filesWalked, MAX_FILES), truncated, lookedFor: Object.values(FRAMEWORK_LABEL) };
}
