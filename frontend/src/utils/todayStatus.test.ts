import type { AccountDto, SparkTarget } from '../types';
import { cstDate, getTodaySparkStatus } from './todayStatus';

const now = new Date('2026-10-14T16:00:01Z');
const target = { is_sparked_today: true } as SparkTarget;
const cases: [string, Partial<SparkTarget>, string][] = [
  ['旧布尔值无日期', {}, 'UNKNOWN'],
  ['昨天检测且今天改了昵称', { today_checked_at: '2026-10-14T15:59:59Z', updated_at: now.toISOString() }, 'UNKNOWN'],
  ['北京时间零点已发', { today_checked_at: '2026-10-14T16:00:00Z' }, 'SUCCESS'],
  ['北京时间当天未发', { is_sparked_today: false, today_checked_at: now.toISOString() }, 'PENDING'],
  ['检测失败清空状态', { is_sparked_today: null, today_checked_at: null }, 'UNKNOWN'],
  ['无效日期', { today_checked_at: 'invalid' }, 'UNKNOWN'],
  ['未来日期', { today_checked_at: '2026-10-14T16:00:02Z' }, 'UNKNOWN'],
  ['系统昨天成功', { last_status: 'SUCCESS', last_sent_at: '2026-10-14T15:59:59Z' }, 'UNKNOWN'],
  ['系统今天成功', { last_status: 'SUCCESS', last_sent_at: now.toISOString() }, 'SUCCESS'],
  ['系统今天失败', { last_status: 'FAILED', last_sent_at: now.toISOString() }, 'FAILED'],
  ['失败不能掩盖当天已发', { last_status: 'FAILED', last_sent_at: now.toISOString(), today_checked_at: now.toISOString() }, 'SUCCESS'],
];
for (const [name, patch, expected] of cases) {
  const actual = getTodaySparkStatus({ ...target, ...patch }, now).code;
  if (actual !== expected) throw new Error(`${name}: ${actual} != ${expected}`);
}
if (cstDate(now) !== '2026-10-15') throw new Error('北京时间日期转换错误');
let isolationCases = 0;
for (const status of ['MISSING', 'INVALID', 'EXPIRED', 'AVAILABLE'] as const) {
  for (const expires of [null, now.getTime() / 1000 - 1, now.getTime() / 1000 + 600]) {
    const account = { im_history_status: status, im_history_expires_at: expires } as AccountDto;
    for (const [name, patch, expected] of cases) {
      const actual = getTodaySparkStatus({ ...target, ...patch }, now, account).code;
      if (actual !== expected) throw new Error(`${status}/${expires}/${name}: 账号 IM 状态污染条目 ${actual} != ${expected}`);
      isolationCases++;
    }
  }
}
const available = { im_history_status: 'AVAILABLE', im_history_expires_at: now.getTime() / 1000 + 600 } as AccountDto;
if (getTodaySparkStatus(target, new Date(now.getTime() + 602000), available).code !== 'UNKNOWN') throw new Error('IM 时钟过期不能改变目标状态');
const rows = cases.map(([,patch]) => ({ ...target, ...patch }));
const before = JSON.stringify(rows);
rows.forEach(row => getTodaySparkStatus(row, now, { im_history_status: 'EXPIRED' } as AccountDto));
if (JSON.stringify(rows) !== before) throw new Error('状态展示不能修改目标数据');
console.log(`账号 IM 状态隔离 ${isolationCases} 个用例、时钟过期与数据不变检查通过`);
console.log(`今日状态 ${cases.length} 个用例及北京时间转换通过`);
