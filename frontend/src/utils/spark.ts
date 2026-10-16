/**
 * 抖音官方 Web 火花状态对齐与解析工具
 * 
 * 官方规则：
 * 1. 连续互动满 3 天及以上：火花正式点亮，显示「🔥 {天数} 天」或「🔥 已点亮 {天数} 天」
 * 2. 连续互动 2 天：点亮中，显示「🔥 连续中 2/3」
 * 3. 连续互动 1 天：点亮中，显示「🔥 连续中 1/3」
 * 4. 未连续互动或未点亮：显示「未点亮」
 */

export interface SparkStatusInfo {
  status: 'LIT' | 'PROGRESS_2' | 'PROGRESS_1' | 'RECOVER' | 'UNLIT';
  label: string; // 完整文案，如 "已点亮 62 天"、"重燃中 2/3"、"连续中 1/3"、"未点亮"
  shortLabel: string; // 简略文案，如 "62 天"、"重燃中 2/3"、"连续中 1/3"、"未点亮"
  badgeClass: string;
  isLit: boolean;
  isInProgress: boolean;
  isRecover: boolean;
}

export function parseSparkStatus(days?: number | null, desc?: string | null): SparkStatusInfo {
  const d = typeof days === 'number' ? days : 0;
  const descStr = (desc || '').trim();

  // 1. 重燃中 (Recovering streak, e.g. "重燃中 1/3", "重燃中 2/3")
  if (descStr.includes('重燃')) {
    return {
      status: 'RECOVER',
      label: descStr.startsWith('重燃中') ? descStr : `重燃中 ${descStr}`,
      shortLabel: descStr,
      badgeClass: 'text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800/60 font-semibold',
      isLit: true,
      isInProgress: true,
      isRecover: true,
    };
  }

  // 2. 已点亮 (满3天及以上正式点亮)
  if (descStr.includes('已点亮') || (!descStr && d >= 3) || (descStr && d >= 3 && !descStr.includes('未点亮') && !descStr.includes('连续中'))) {
    const finalDays = d >= 3 ? d : (parseInt(descStr.replace(/[^0-9]/g, ''), 10) || d);
    return {
      status: 'LIT',
      label: `已点亮 ${finalDays} 天`,
      shortLabel: `${finalDays} 天`,
      badgeClass: 'text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-950/40 border-orange-200/60 dark:border-orange-900/50 font-bold',
      isLit: true,
      isInProgress: false,
      isRecover: false,
    };
  }

  // 3. 连续中 2/3 (未点亮但已互聊 2 天)
  if (descStr.includes('2/3') || (!descStr && d === 2)) {
    return {
      status: 'PROGRESS_2',
      label: '连续中 2/3',
      shortLabel: '连续中 2/3',
      badgeClass: 'text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/40 border-amber-200/60 dark:border-amber-900/50 font-medium',
      isLit: true,
      isInProgress: true,
      isRecover: false,
    };
  }

  // 4. 连续中 1/3 (未点亮但已互聊 1 天)
  if (descStr.includes('1/3') || (!descStr && d === 1)) {
    return {
      status: 'PROGRESS_1',
      label: '连续中 1/3',
      shortLabel: '连续中 1/3',
      badgeClass: 'text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/40 border-amber-200/60 dark:border-amber-900/50 font-medium',
      isLit: true,
      isInProgress: true,
      isRecover: false,
    };
  }

  // 5. 未点亮
  return {
    status: 'UNLIT',
    label: '未点亮',
    shortLabel: '未点亮',
    badgeClass: 'text-slate-400 dark:text-slate-500 bg-slate-100 dark:bg-slate-800/60 border-slate-200 dark:border-slate-700/60 font-normal',
    isLit: false,
    isInProgress: false,
    isRecover: false,
  };
}
