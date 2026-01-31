/**
 * Project Cordelia - Policy Engine
 *
 * R2 implementation: inline PEP (Policy Enforcement Point).
 * Interface designed for R3 PDP/PEP/PIP separation.
 *
 * Policy engine is pure -- it does NOT log. Callers log to access_log.
 * This keeps the engine testable without storage side effects.
 */

import type { StorageProvider } from './storage.js';
import { getStorageProvider } from './storage.js';

export interface PolicyRequest {
  entity_id: string;
  action: 'read' | 'write' | 'delete' | 'share';
  resource_type: string;
  resource_id?: string;
  group_id?: string;
  owner_id?: string;
}

export interface PolicyDecision {
  allowed: boolean;
  reason?: string;
  audit_detail?: string;
}

export interface PolicyEngine {
  evaluate(request: PolicyRequest): Promise<PolicyDecision>;
}

/**
 * R2 inline policy engine. Single-process, direct storage queries.
 * R3 replaces this with DistributedPolicyEngine behind the same interface.
 */
export class InlinePolicyEngine implements PolicyEngine {
  private storage: StorageProvider;

  constructor(storage?: StorageProvider) {
    this.storage = storage || getStorageProvider();
  }

  async evaluate(request: PolicyRequest): Promise<PolicyDecision> {
    const { entity_id, action, group_id, owner_id } = request;

    // Rule 1: No entity = unauthenticated = denied
    if (!entity_id) {
      return { allowed: false, reason: 'unauthenticated', audit_detail: 'denied: no entity_id' };
    }

    // Rule 2: No group = private memory -- entity must be owner
    if (!group_id) {
      if (!owner_id) {
        // No owner means new item being created -- allowed
        return { allowed: true, audit_detail: 'allowed: new private item' };
      }
      if (entity_id === owner_id) {
        return { allowed: true, audit_detail: 'allowed: owner access' };
      }
      return { allowed: false, reason: 'not_owner', audit_detail: `denied: entity ${entity_id} is not owner ${owner_id}` };
    }

    // Rule 3: Group memory -- check membership
    const membership = await this.storage.getMembership(group_id, entity_id);
    if (!membership) {
      return { allowed: false, reason: 'not_member', audit_detail: `denied: entity ${entity_id} not a member of group ${group_id}` };
    }

    // Rule 4: Viewer cannot write/delete/share
    if (membership.role === 'viewer' && (action === 'write' || action === 'delete' || action === 'share')) {
      return { allowed: false, reason: 'viewer_read_only', audit_detail: `denied: viewer cannot ${action}` };
    }

    // Rule 5: EMCON posture blocks writes/shares
    if (membership.posture === 'emcon' && (action === 'write' || action === 'share')) {
      return { allowed: false, reason: 'emcon', audit_detail: `denied: entity in EMCON posture cannot ${action}` };
    }

    return { allowed: true, audit_detail: `allowed: ${membership.role} role permits ${action}` };
  }
}

/**
 * Context binding: resolve working directory to bound group_id(s).
 * Returns the group_id if cwd matches a binding, undefined otherwise.
 * Matches longest prefix first (most specific binding wins).
 */
export function resolveContextBinding(
  cwd: string | undefined,
  bindings: Record<string, string> | undefined,
): string | undefined {
  if (!cwd || !bindings) return undefined;

  // Normalize: ensure trailing slash for prefix matching
  const normalizedCwd = cwd.endsWith('/') ? cwd : cwd + '/';

  let bestMatch: string | undefined;
  let bestLen = 0;

  for (const [dirPath, groupId] of Object.entries(bindings)) {
    const normalizedDir = dirPath.endsWith('/') ? dirPath : dirPath + '/';
    if (normalizedCwd.startsWith(normalizedDir) && normalizedDir.length > bestLen) {
      bestMatch = groupId;
      bestLen = normalizedDir.length;
    }
  }

  return bestMatch;
}

/**
 * Check if a group_id is allowed in the current context.
 * If no bindings exist, all groups are visible (backward compat).
 * If bindings exist but no cwd, only private items are visible.
 * If bindings exist and cwd is bound, only the bound group is visible.
 */
export function isGroupVisibleInContext(
  groupId: string,
  cwd: string | undefined,
  bindings: Record<string, string> | undefined,
): boolean {
  // No bindings = all groups visible (backward compat)
  if (!bindings || Object.keys(bindings).length === 0) return true;

  // No cwd = private only
  if (!cwd) return false;

  const boundGroup = resolveContextBinding(cwd, bindings);
  return boundGroup === groupId;
}

// Singleton pattern matching storage.ts
let activePolicyEngine: PolicyEngine | null = null;

export function getPolicyEngine(): PolicyEngine {
  if (!activePolicyEngine) {
    activePolicyEngine = new InlinePolicyEngine();
  }
  return activePolicyEngine;
}

export function setPolicyEngine(engine: PolicyEngine): void {
  activePolicyEngine = engine;
}
