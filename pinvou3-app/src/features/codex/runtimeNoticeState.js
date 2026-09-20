export function runtimeNoticeMode(status, latestUpgradeDeferred = false) {
  if (!status) return 'checking';
  if (!status.bridge_ready) return 'bridge_unavailable';
  if (!status.installed || status.update_required || (status.update_available && !latestUpgradeDeferred)) return 'install';
  if (!status.authenticated) return 'login';
  if (status.error) return 'error';
  return 'ready';
}

export function runtimeOperationFor(operations, agentId) {
  if (!agentId || !operations) return '';
  return operations[agentId] || '';
}

export function runtimeInstallInProgress(status, operation = '') {
  return Boolean(status?.installing || operation === 'install');
}

export function runtimeLoginInProgress(status, operation = '') {
  return Boolean(
    status?.login_in_progress
      || operation === 'login'
      || operation === 'switch-account',
  );
}

const ACP_AUTHENTICATION_FAILURE = /HTTP\s*401|authentication[_ ]failed|authentication required|failed to authenticate|oauth.{0,80}expired|not logged in|model\.not_configured|llm not set|send\s+["']?\/login|尚未完成模型配置|请重新登录/i;

export function isAcpAuthenticationFailure(envelope) {
  if (envelope?.event?.type !== 'turn_completed') return false;
  const error = String(envelope.event?.data?.error || '');
  return ACP_AUTHENTICATION_FAILURE.test(error);
}

export function classifyAcpServiceFailure(envelope) {
  if (envelope?.event?.type !== 'turn_completed') return null;
  const detail = String(envelope.event?.data?.error || '').trim();
  if (!detail) return null;
  let kind = 'service';
  if (/HTTP\s*402|会员.{0,12}(权益|额度|到期|失效)|订阅.{0,12}(到期|失效)|payment required/i.test(detail)) {
    kind = 'entitlement';
  } else if (/HTTP\s*429|rate.?limit|quota|额度.{0,12}(不足|用尽)|用量.{0,12}(超出|耗尽)/i.test(detail)) {
    kind = 'quota';
  } else if (ACP_AUTHENTICATION_FAILURE.test(detail)) {
    kind = 'authentication';
  } else if (/network|connection|timeout|timed out|网络|连接.{0,8}(失败|超时)/i.test(detail)) {
    kind = 'network';
  }
  return {
    kind,
    detail,
    key: `${envelope.seq || ''}:${envelope.timestamp || ''}:${detail}`,
  };
}

// Agent 侧运行时提示：适配器自己的报错原文，以及宿主回合看门狗的兜底动作。
// 它们不是「模型服务故障」，要表达的是「知情 + 可以继续」，因此单独一层。
const AGENT_RUNTIME_NOTICE_KINDS = new Set([
  'agent_stderr',
  'agent_stall',
  'agent_stall_cancel',
  'agent_stall_settled',
  'cancel_timeout',
]);

/**
 * 最近一条 Agent 侧运行时提示；用户发出下一条消息（更新的 turn_started）
 * 之后视为过期，避免旧提示跟着整段会话。
 */
export function latestAgentRuntimeNotice(events) {
  if (!Array.isArray(events)) return null;
  let notice = null;
  for (const envelope of events) {
    const type = envelope?.event?.type;
    if (type === 'runtime_notice') {
      const kind = String(envelope?.event?.data?.kind || '');
      if (AGENT_RUNTIME_NOTICE_KINDS.has(kind)) notice = envelope;
      continue;
    }
    if (type === 'turn_started' && notice
      && Number(envelope.seq || 0) > Number(notice.seq || 0)) {
      notice = null;
    }
  }
  if (!notice) return null;
  const data = notice.event.data || {};
  return {
    kind: String(data.kind || ''),
    agent: String(data.agent || ''),
    detail: String(data.detail || ''),
    quietSeconds: Number(data.quietSeconds || 0),
    key: `${notice.seq || ''}:${notice.timestamp || ''}`,
  };
}
