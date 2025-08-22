'use client';

import React, { useEffect, useRef } from 'react';
import { Terminal, Trash2, AlertCircle, CheckCircle, Info, AlertTriangle } from 'lucide-react';
import { useIDEStore } from '@/store/ide-store';
import { clsx } from 'clsx';

export const Console: React.FC = () => {
  const { consoleMessages, clearConsole } = useIDEStore();
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [consoleMessages]);

  const getIcon = (type: string) => {
    switch (type) {
      case 'error':
        return <AlertCircle size={14} className="text-red-400" />;
      case 'warning':
        return <AlertTriangle size={14} className="text-yellow-400" />;
      case 'success':
        return <CheckCircle size={14} className="text-green-400" />;
      default:
        return <Info size={14} className="text-blue-400" />;
    }
  };

  const getMessageClass = (type: string) => {
    switch (type) {
      case 'error':
        return 'text-red-300';
      case 'warning':
        return 'text-yellow-300';
      case 'success':
        return 'text-green-300';
      default:
        return 'text-gray-300';
    }
  };

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  return (
    <div className="h-full bg-gray-900 text-gray-100 flex flex-col">
      <div className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700">
        <div className="flex items-center gap-2">
          <Terminal size={16} />
          <span className="text-sm font-medium">Console</span>
        </div>
        <button
          onClick={clearConsole}
          className="p-1 hover:bg-gray-700 rounded transition-colors"
          title="Clear Console"
        >
          <Trash2 size={14} />
        </button>
      </div>

      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-4 font-mono text-xs"
      >
        {consoleMessages.length === 0 ? (
          <div className="text-gray-500 italic">
            Console output will appear here...
          </div>
        ) : (
          <div className="space-y-1">
            {consoleMessages.map((msg) => (
              <div
                key={msg.id}
                className="flex items-start gap-2 py-1"
              >
                <span className="text-gray-500">
                  [{formatTime(msg.timestamp)}]
                </span>
                {getIcon(msg.type)}
                <span className={clsx('flex-1 break-all', getMessageClass(msg.type))}>
                  {msg.message}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};