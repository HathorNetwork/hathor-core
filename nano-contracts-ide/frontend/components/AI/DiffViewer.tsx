'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Check, X, Eye } from 'lucide-react';
import { Editor } from '@monaco-editor/react';
import * as monaco from 'monaco-editor';
import { createTwoFilesPatch } from 'diff';

interface DiffViewerProps {
  originalCode: string;
  modifiedCode: string;
  fileName: string;
  onApply: (modifiedCode: string) => void;
  onReject: () => void;
}

export const DiffViewer: React.FC<DiffViewerProps> = ({
  originalCode,
  modifiedCode,
  fileName,
  onApply,
  onReject
}) => {
  const [viewMode, setViewMode] = useState<'diff' | 'preview'>('diff');
  const editorRef = useRef<monaco.editor.IStandaloneDiffEditor | null>(null);

  // Generate diff for display purposes
  const diff = createTwoFilesPatch(
    fileName,
    fileName,
    originalCode,
    modifiedCode,
    'Original',
    'Modified',
    { context: 3 }
  );

  // Calculate diff statistics
  const originalLines = originalCode.split('\n');
  const modifiedLines = modifiedCode.split('\n');
  const linesAdded = modifiedLines.length - originalLines.length;
  const linesModified = diff.split('\n').filter(line => line.startsWith('+')).length - 1; // -1 for header

  return (
    <div className="border border-blue-500 rounded-lg bg-gray-900 overflow-hidden">
      {/* Header */}
      <div className="bg-blue-600 px-4 py-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-white font-medium text-sm">
            📝 Code Suggestion for {fileName}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setViewMode(viewMode === 'diff' ? 'preview' : 'diff')}
            className="px-2 py-1 text-xs bg-blue-700 text-white rounded hover:bg-blue-800 transition-colors flex items-center gap-1"
          >
            <Eye size={12} />
            {viewMode === 'diff' ? 'Preview' : 'Diff'}
          </button>
          <button
            onClick={() => onApply(modifiedCode)}
            className="px-3 py-1 text-xs bg-green-600 text-white rounded hover:bg-green-700 transition-colors flex items-center gap-1"
          >
            <Check size={12} />
            Apply
          </button>
          <button
            onClick={onReject}
            className="px-3 py-1 text-xs bg-red-600 text-white rounded hover:bg-red-700 transition-colors flex items-center gap-1"
          >
            <X size={12} />
            Reject
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="h-64">
        {viewMode === 'diff' ? (
          <div 
            style={{ height: '100%', width: '100%' }}
            ref={(el) => {
              if (el && !editorRef.current) {
                // Dynamically import monaco and create diff editor
                import('monaco-editor').then((monacoInstance) => {
                  const diffEditor = monacoInstance.editor.createDiffEditor(el, {
                    theme: 'vs-dark',
                    readOnly: true,
                    minimap: { enabled: false },
                    fontSize: 12,
                    scrollBeyondLastLine: false,
                    renderSideBySide: true,
                    enableSplitViewResizing: true,
                    renderOverviewRuler: false,
                    diffCodeLens: true,
                    ignoreTrimWhitespace: false,
                  });

                  // Set the models
                  const originalModel = monacoInstance.editor.createModel(originalCode, 'python');
                  const modifiedModel = monacoInstance.editor.createModel(modifiedCode, 'python');

                  diffEditor.setModel({
                    original: originalModel,
                    modified: modifiedModel
                  });

                  // Store reference
                  editorRef.current = diffEditor;
                });
              }
            }}
          />
        ) : (
          <Editor
            height="100%"
            language="python"
            theme="vs-dark"
            value={modifiedCode}
            options={{
              readOnly: true,
              minimap: { enabled: false },
              fontSize: 12,
              scrollBeyondLastLine: false,
            }}
          />
        )}
      </div>

      {/* Diff Summary */}
      <div className="border-t border-gray-700 px-4 py-2 bg-gray-800">
        <div className="text-xs text-gray-400">
          <span className="text-green-400">+{linesModified} lines changed</span>
          {linesAdded !== 0 && (
            <>
              {' • '}
              <span className={linesAdded > 0 ? 'text-green-400' : 'text-red-400'}>
                {linesAdded > 0 ? `+${linesAdded}` : linesAdded} lines total
              </span>
            </>
          )}
          {' • '}
          <span className="text-gray-400">Click "Apply" to accept these changes or "Reject" to dismiss</span>
        </div>
      </div>
    </div>
  );
};