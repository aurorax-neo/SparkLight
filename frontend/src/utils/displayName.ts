/** 名字后面跟备注：昵称 (备注)。备注为空或与昵称相同则不重复。 */
export function formatDisplayName(name?: string | null, remark?: string | null): string {
  const n = (name || '').trim();
  const r = (remark || '').trim();
  if (!n) return r || '未命名';
  if (!r || r === n || n.includes(`(${r})`)) return n;
  return `${n} (${r})`;
}

const PLACEHOLDER_ALIAS = new Set(['抖音账号']);

/** 账号主名用抖音当前昵称；别名只有在用户另行填写、且不同于昵称时才放进括号。 */
export function accountDisplayName(nickname?: string | null, alias?: string | null): string {
  const nick = (nickname || '').trim();
  const note = (alias || '').trim();
  if (!nick) return note || '未命名';
  if (!note || note === nick || PLACEHOLDER_ALIAS.has(note)) return nick;
  return `${nick} (${note})`;
}
