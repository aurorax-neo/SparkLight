import React from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { ModalPortal } from './ModalPortal';

interface Props {
  isOpen: boolean;
  title: string;
  description: string;
  confirmText?: string;
  cancelText?: string;
  isDanger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmModal: React.FC<Props> = ({
  isOpen,
  title,
  description,
  confirmText = '确定',
  cancelText = '取消',
  isDanger = false,
  onConfirm,
  onCancel,
}) => {
  if (!isOpen) return null;

  return (
    <ModalPortal>
      <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-sm rounded-2xl bg-white dark:bg-slate-900 p-6 shadow-2xl border border-slate-200 dark:border-slate-800 animate-in fade-in zoom-in-95 duration-150">
        <button
          onClick={onCancel}
          className="absolute right-4 top-4 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-3 mb-3">
          <div
            className={`p-2.5 rounded-xl ${
              isDanger
                ? 'bg-rose-500/10 text-rose-500 dark:bg-rose-500/20'
                : 'bg-amber-500/10 text-amber-500 dark:bg-amber-500/20'
            }`}
          >
            <AlertTriangle className="w-5 h-5" />
          </div>
          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">{title}</h3>
        </div>

        <p className="text-xs text-slate-600 dark:text-slate-400 mb-5 leading-relaxed">
          {description}
        </p>

        <div className="flex gap-2.5">
          <button
            type="button"
            onClick={onCancel}
            className="flex-1 px-4 py-2 text-xs font-medium rounded-xl border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
          >
            {cancelText}
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className={`flex-1 px-4 py-2 text-xs font-semibold rounded-xl text-white transition shadow-sm ${
              isDanger
                ? 'bg-rose-600 hover:bg-rose-700 shadow-rose-600/20'
                : 'bg-orange-500 hover:bg-orange-600 shadow-orange-500/20'
            }`}
          >
            {confirmText}
          </button>
        </div>
      </div>
      </div>
    </ModalPortal>
  );
};
