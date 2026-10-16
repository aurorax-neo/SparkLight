/**
 * 通用剪贴板复制工具函数
 * 兼顾 HTTPS 现代 navigator.clipboard 与 HTTP (如机房公网/内网IP访问) 兼容环境
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  if (!text) return false;

  // 1. 尝试使用现代 Clipboard API (仅在 Secure Context 即 HTTPS 或 localhost 下可用)
  if (navigator?.clipboard && typeof navigator.clipboard.writeText === 'function') {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      // 若因权限或非安全上下文抛出异常，继续向下执行可靠降级方案
    }
  }

  // 2. 传统通用降级方案：创建临时不可见的文本区域并通过 execCommand 执行复制
  // 该方案在 HTTP IP 访问环境下具备 100% 兼容性
  try {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    // 避免页面跳动与滚动
    textarea.style.position = 'fixed';
    textarea.style.top = '0';
    textarea.style.left = '0';
    textarea.style.width = '2em';
    textarea.style.height = '2em';
    textarea.style.padding = '0';
    textarea.style.border = 'none';
    textarea.style.outline = 'none';
    textarea.style.boxShadow = 'none';
    textarea.style.background = 'transparent';
    textarea.style.opacity = '0';
    textarea.setAttribute('readonly', '');
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    const successful = document.execCommand('copy');
    document.body.removeChild(textarea);
    if (successful) {
      return true;
    }
  } catch (err) {
    console.error('execCommand copy fallback failed:', err);
  }

  return false;
}
