import type { SparkTarget } from '../types';

export interface TargetRefreshResult { confirmed: boolean; message: string }
export interface TargetRefreshSummary {
  confirmed: number;
  unconfirmed: number;
  skipped: number;
  failures: { targetId: string; name: string; message: string }[];
}

/** 顺序复用单条刷新；账号失败后不继续请求该账号，不触发好友发现或发送。 */
export async function refreshTargetsSequentially(
  targets: SparkTarget[],
  refresh: (target: SparkTarget) => Promise<TargetRefreshResult>,
): Promise<TargetRefreshSummary> {
  const result: TargetRefreshSummary = { confirmed: 0, unconfirmed: 0, skipped: 0, failures: [] };
  const stoppedAccounts = new Set<string>();
  for (const target of targets) {
    if (stoppedAccounts.has(target.account_id)) { result.skipped += 1; continue; }
    try {
      const response = await refresh(target);
      if (response.confirmed) result.confirmed += 1;
      else {
        result.unconfirmed += 1;
        result.failures.push({ targetId: target.id, name: target.remark_name || target.target_nickname, message: response.message });
        stoppedAccounts.add(target.account_id);
      }
    } catch (error) {
      result.unconfirmed += 1;
      result.failures.push({ targetId: target.id, name: target.remark_name || target.target_nickname,
        message: error instanceof Error ? error.message : '请求失败，结果未确认' });
      stoppedAccounts.add(target.account_id);
    }
  }
  return result;
}

/**
 * 并发刷新目标状态：不同账号之间完全并行；同一账号内部按有界并发度（默认 4）并发执行，
 * 首检由后端批量拉取并缓存整账号火花状态，若某账号失败则自动熔断跳过该账号剩余排队目标。
 */
export async function refreshTargetsConcurrently(
  targets: SparkTarget[],
  refresh: (target: SparkTarget) => Promise<TargetRefreshResult>,
  concurrencyPerAccount = 4,
): Promise<TargetRefreshSummary> {
  const result: TargetRefreshSummary = { confirmed: 0, unconfirmed: 0, skipped: 0, failures: [] };
  if (!targets.length) return result;

  const byAccount = new Map<string, SparkTarget[]>();
  for (const target of targets) {
    const list = byAccount.get(target.account_id) || [];
    list.push(target);
    byAccount.set(target.account_id, list);
  }

  const limit = Math.max(1, concurrencyPerAccount);

  await Promise.all(
    Array.from(byAccount.values()).map(async (accountTargets) => {
      let cursor = 0;
      let stopped = false;

      const worker = async () => {
        while (cursor < accountTargets.length) {
          const idx = cursor++;
          const target = accountTargets[idx];
          if (stopped) {
            result.skipped += 1;
            continue;
          }
          try {
            const response = await refresh(target);
            if (response.confirmed) {
              result.confirmed += 1;
            } else {
              result.unconfirmed += 1;
              result.failures.push({
                targetId: target.id,
                name: target.remark_name || target.target_nickname,
                message: response.message,
              });
              stopped = true;
            }
          } catch (error) {
            result.unconfirmed += 1;
            result.failures.push({
              targetId: target.id,
              name: target.remark_name || target.target_nickname,
              message: error instanceof Error ? error.message : '请求失败，结果未确认',
            });
            stopped = true;
          }
        }
      };

      const workersCount = Math.min(limit, accountTargets.length);
      await Promise.all(Array.from({ length: workersCount }, () => worker()));
    }),
  );

  return result;
}

export function refreshSummaryMessage(result: TargetRefreshSummary): string {
  if (!result.failures.length) return `已刷新 ${result.confirmed} 个目标`;
  const first = result.failures[0];
  return `已刷新 ${result.confirmed} 个目标，${result.unconfirmed} 个未确认${result.skipped ? `，${result.skipped} 个已停止` : ''}；${first.name}：${first.message}`;
}
