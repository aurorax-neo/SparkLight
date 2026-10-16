import type { SparkTarget } from '../types';
import { refreshSummaryMessage, refreshTargetsSequentially } from './refreshTargets';

const targets = [
  { id: 'a1', account_id: 'a', target_nickname: '目标一' },
  { id: 'a2', account_id: 'a', target_nickname: '目标二' },
  { id: 'b1', account_id: 'b', target_nickname: '目标三' },
] as SparkTarget[];
function assert(value: unknown, message: string) { if (!value) throw new Error(message); }
async function main() {
  const calls: string[] = [];
  let pending = 0;
  const success = await refreshTargetsSequentially(targets, async (target) => {
    assert(pending === 0, '批量刷新不应并发请求'); pending += 1;
    await Promise.resolve(); calls.push(target.id); pending -= 1;
    return { confirmed: true, message: '已更新' };
  });
  assert(calls.join(',') === 'a1,a2,b1', '应顺序刷新全部目标，包括未启用目标');
  assert(success.confirmed === 3 && !success.failures.length, '成功计数错误');
  assert(refreshSummaryMessage(success) === '已刷新 3 个目标', '成功文案错误');
  const scoped = await refreshTargetsSequentially(targets.filter(t => t.account_id === 'b'), async t => {
    assert(t.id === 'b1', '账号筛选越界'); return { confirmed: true, message: '已更新' };
  });
  assert(scoped.confirmed === 1, '筛选计数错误');
  calls.length = 0;
  const partial = await refreshTargetsSequentially(targets, async t => {
    calls.push(t.id);
    if (t.id === 'a1') return { confirmed: false, message: 'IM 身份凭证获取失败' };
    return { confirmed: true, message: '已更新' };
  });
  assert(calls.join(',') === 'a1,b1', '失败后应停止该账号，继续其他账号');
  assert(partial.confirmed === 1 && partial.unconfirmed === 1 && partial.skipped === 1, '部分失败计数错误');
  assert(refreshSummaryMessage(partial).includes('目标一：IM 身份凭证获取失败'), '必须保留真实原因，不猜测风控');
  const rejected = await refreshTargetsSequentially(targets, async () => { throw new Error('网络请求超时'); });
  assert(rejected.unconfirmed === 2 && rejected.skipped === 1, '异常计数错误');
  assert(rejected.failures[0].message === '网络请求超时', '异常原因丢失');
  const empty = await refreshTargetsSequentially([], async () => { throw new Error('不得调用'); });
  assert(empty.confirmed === 0 && !empty.failures.length, '空列表不应请求');
  console.log('批量刷新：顺序、范围、共享单条回调、失败停止、原因保留、空列表检查通过');
}
void main().catch(error => { console.error(error); throw error; });
