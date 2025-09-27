'use client';

import React from 'react';
import { Play, Zap, FileCode, Settings, HelpCircle, Loader2 } from 'lucide-react';
import { clsx } from 'clsx';

interface ToolbarProps {
  onCompile: () => void;
  onExecute: () => void;
  isCompiling: boolean;
  isExecuting: boolean;
  fileName?: string;
}

export const Toolbar: React.FC<ToolbarProps> = ({
  onCompile,
  onExecute,
  isCompiling,
  isExecuting,
  fileName,
}) => {
  return (
    <div className="bg-gray-800 border-b border-gray-700 px-4 py-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {/* Logo */}
          <div className="flex items-center gap-2">
            <FileCode size={20} className="text-hathor-500" />
            <span className="text-white font-bold">Hathor Nano Contracts IDE</span>
          </div>

          {/* Current file */}
          {fileName && (
            <div className="text-gray-400 text-sm">
              <span className="text-gray-500">Editing:</span> {fileName}
            </div>
          )}
        </div>

        <div className="flex items-center gap-2">
          {/* Compile Button */}
          <button
            onClick={onCompile}
            disabled={isCompiling || isExecuting}
            className={clsx(
              'flex items-center gap-2 px-4 py-1.5 rounded text-sm font-medium transition-colors',
              isCompiling || isExecuting
                ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                : 'bg-blue-600 text-white hover:bg-blue-700'
            )}
          >
            {isCompiling ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <Zap size={16} />
            )}
            {isCompiling ? 'Compiling...' : 'Compile'}
          </button>

          {/* Run Button */}
          <button
            onClick={onExecute}
            disabled={isCompiling || isExecuting}
            className={clsx(
              'flex items-center gap-2 px-4 py-1.5 rounded text-sm font-medium transition-colors',
              isCompiling || isExecuting
                ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                : 'bg-green-600 text-white hover:bg-green-700'
            )}
          >
            {isExecuting ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <Play size={16} />
            )}
            {isExecuting ? 'Executing...' : 'Quick Execute'}
          </button>

          <div className="border-l border-gray-600 h-6 mx-2" />

          {/* Settings Button */}
          <button
            className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
            title="Settings"
          >
            <Settings size={18} />
          </button>

          {/* Help Button */}
          <button
            className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
            title="Help"
          >
            <HelpCircle size={18} />
          </button>
        </div>
      </div>
    </div>
  );
};