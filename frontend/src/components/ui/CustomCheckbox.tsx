import React from 'react';
import { Check } from 'lucide-react';

interface Props {
  checked: boolean;
  onChange: (checked: boolean) => void;
  className?: string;
  disabled?: boolean;
}

export const CustomCheckbox: React.FC<Props> = ({
  checked,
  onChange,
  className = '',
  disabled = false,
}) => {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`w-4 h-4 rounded-md border flex items-center justify-center transition-all ${
        checked
          ? 'bg-orange-500 border-orange-500 text-white shadow-sm shadow-orange-500/30'
          : 'border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 hover:border-orange-400'
      } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'} ${className}`}
    >
      {checked && <Check className="w-3 h-3 stroke-[3]" />}
    </button>
  );
};
