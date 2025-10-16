'use client';

import React, { useRef, useEffect } from 'react';
import Editor, { Monaco } from '@monaco-editor/react';
import { useIDEStore } from '@/store/ide-store';

export const CodeEditor: React.FC = () => {
  const editorRef = useRef<any>(null);
  const monacoRef = useRef<Monaco | null>(null);
  
  const { files, activeFileId, updateFile } = useIDEStore();
  const activeFile = files.find((f) => f.id === activeFileId);

  useEffect(() => {
    if (monacoRef.current && editorRef.current) {
      // Set up Python language configuration for nano contracts
      monacoRef.current.languages.setMonarchTokensProvider('python', {
        keywords: [
          'Blueprint', 'public', 'view', 'fallback', 'Context',
          'def', 'class', 'return', 'if', 'else', 'elif', 'for', 'while',
          'import', 'from', 'as', 'try', 'except', 'raise', 'pass',
          'True', 'False', 'None', 'self', 'int', 'str', 'bool', 'float',
        ],
        
        tokenizer: {
          root: [
            [/@(public|view|fallback)/, 'decorator'],
            [/[a-z_$][\w$]*/, {
              cases: {
                '@keywords': 'keyword',
                '@default': 'identifier'
              }
            }],
            [/"([^"\\]|\\.)*$/, 'string.invalid'],
            [/"/, 'string', '@string'],
            [/'([^'\\]|\\.)*$/, 'string.invalid'],
            [/'/, 'string', '@stringSingle'],
            [/#.*$/, 'comment'],
          ],
          
          string: [
            [/[^\\"]+/, 'string'],
            [/\\./, 'string.escape'],
            [/"/, 'string', '@pop']
          ],
          
          stringSingle: [
            [/[^\\']+/, 'string'],
            [/\\./, 'string.escape'],
            [/'/, 'string', '@pop']
          ],
        }
      });
    }
  }, []);

  const handleEditorDidMount = (editor: any, monaco: Monaco) => {
    editorRef.current = editor;
    monacoRef.current = monaco;
    
    // Configure Python language features
    monaco.languages.registerCompletionItemProvider('python', {
      provideCompletionItems: (model, position) => {
        const suggestions = [
          {
            label: 'Blueprint',
            kind: monaco.languages.CompletionItemKind.Class,
            insertText: 'Blueprint',
            documentation: 'Base class for nano contracts',
          },
          {
            label: '@public',
            kind: monaco.languages.CompletionItemKind.Function,
            insertText: '@public\ndef ${1:method_name}(self, ctx: Context) -> None:\n    ${2:pass}',
            insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
            documentation: 'Decorator for public methods',
          },
          {
            label: '@view',
            kind: monaco.languages.CompletionItemKind.Function,
            insertText: '@view\ndef ${1:method_name}(self) -> ${2:int}:\n    ${3:return 0}',
            insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
            documentation: 'Decorator for view methods',
          },
          {
            label: 'Context',
            kind: monaco.languages.CompletionItemKind.Class,
            insertText: 'Context',
            documentation: 'Execution context for nano contracts',
          },
        ];
        
        return { suggestions };
      },
    });
  };

  const handleChange = (value: string | undefined) => {
    if (activeFileId && value !== undefined) {
      updateFile(activeFileId, value);
    }
  };

  if (!activeFile) {
    return (
      <div className="flex items-center justify-center h-full bg-gray-900 text-gray-400">
        <p>No file selected</p>
      </div>
    );
  }

  return (
    <div className="h-full">
      <Editor
        height="100%"
        defaultLanguage="python"
        language={activeFile.language}
        value={activeFile.content}
        onChange={handleChange}
        onMount={handleEditorDidMount}
        theme="vs-dark"
        options={{
          minimap: { enabled: false },
          fontSize: 14,
          fontFamily: 'JetBrains Mono, Fira Code, Monaco, monospace',
          fontLigatures: true,
          automaticLayout: true,
          scrollBeyondLastLine: false,
          wordWrap: 'on',
          lineNumbers: 'on',
          renderWhitespace: 'selection',
          bracketPairColorization: {
            enabled: true,
          },
          suggest: {
            showKeywords: true,
            showSnippets: true,
          },
        }}
      />
    </div>
  );
};