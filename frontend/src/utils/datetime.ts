const BEIJING_TZ = 'Asia/Shanghai';

function toValidDate(value?: string | number | Date | null): Date | null {
  if (value === null || value === undefined || value === '') return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function extractParts(date: Date): Record<string, string> {
  const formatter = new Intl.DateTimeFormat('zh-CN', {
    timeZone: BEIJING_TZ,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
  const out: Record<string, string> = {};
  for (const part of formatter.formatToParts(date)) {
    if (part.type !== 'literal') {
      out[part.type] = part.value;
    }
  }
  return out;
}

/** 格式化为标准北京时间：YYYY-MM-DD HH:mm:ss */
export function formatBeijingDateTime(value?: string | number | Date | null): string {
  const date = toValidDate(value);
  if (!date) return '-';
  const p = extractParts(date);
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}`;
}

/** 格式化为紧凑北京时间：MM-DD HH:mm（适合表格列与卡片副文案） */
export function formatBeijingShortDateTime(value?: string | number | Date | null): string {
  const date = toValidDate(value);
  if (!date) return '-';
  const p = extractParts(date);
  return `${p.month}-${p.day} ${p.hour}:${p.minute}`;
}

/** 顶部状态栏实时时钟：YYYY-MM-DD HH:mm:ss UTC+8 */
export function formatBeijingClock(date: Date = new Date()): string {
  const p = extractParts(date);
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second} UTC+8`;
}
