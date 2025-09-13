'use client';

import React, { useState } from 'react';
import { FileText, Plus, Trash2, FolderOpen, ChevronRight, ChevronDown } from 'lucide-react';
import { useIDEStore } from '@/store/ide-store';
import { clsx } from 'clsx';

export const FileExplorer: React.FC = () => {
  const { files, activeFileId, setActiveFile, addFile, deleteFile } = useIDEStore();
  const [isExpanded, setIsExpanded] = useState(true);
  const [showNewFileInput, setShowNewFileInput] = useState(false);
  const [newFileName, setNewFileName] = useState('');

  const handleNewFile = () => {
    if (newFileName.trim()) {
      const newFile = {
        id: Date.now().toString(),
        name: newFileName.endsWith('.py') ? newFileName : `${newFileName}.py`,
        content: `from hathor.nanocontracts import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import public, view

class ${newFileName.replace('.py', '').replace(/[^a-zA-Z]/g, '')}(Blueprint):
    """Your contract description here"""
    
    # Contract state variables
    # example_value: int
    
    @public
    def initialize(self, ctx: Context) -> None:
        """Initialize the contract"""
        pass

__blueprint__ = ${newFileName.replace('.py', '').replace(/[^a-zA-Z]/g, '')}`,
        language: 'python',
        path: `/contracts/${newFileName}`,
      };
      
      addFile(newFile);
      setNewFileName('');
      setShowNewFileInput(false);
    }
  };

  const handleDeleteFile = (e: React.MouseEvent, fileId: string) => {
    e.stopPropagation();
    if (files.length > 1) {
      deleteFile(fileId);
    }
  };

  return (
    <div className="h-full bg-gray-900 text-gray-100 p-4">
      <div className="mb-4">
        <div className="flex items-center justify-between mb-2">
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="flex items-center gap-2 hover:text-blue-400 transition-colors"
          >
            {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
            <FolderOpen size={16} />
            <span className="text-sm font-medium">Contracts</span>
          </button>
          <button
            onClick={() => setShowNewFileInput(true)}
            className="p-1 hover:bg-gray-800 rounded transition-colors"
            title="New File"
          >
            <Plus size={16} />
          </button>
        </div>

        {showNewFileInput && (
          <div className="mb-2">
            <input
              type="text"
              value={newFileName}
              onChange={(e) => setNewFileName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleNewFile();
                if (e.key === 'Escape') {
                  setShowNewFileInput(false);
                  setNewFileName('');
                }
              }}
              onBlur={handleNewFile}
              placeholder="filename.py"
              className="w-full px-2 py-1 text-sm bg-gray-800 border border-gray-700 rounded focus:outline-none focus:border-blue-500"
              autoFocus
            />
          </div>
        )}
      </div>

      {isExpanded && (
        <div className="space-y-1">
          {files.map((file) => (
            <div
              key={file.id}
              onClick={() => setActiveFile(file.id)}
              className={clsx(
                'flex items-center justify-between px-2 py-1 rounded cursor-pointer transition-colors group',
                activeFileId === file.id
                  ? 'bg-blue-600 text-white'
                  : 'hover:bg-gray-800'
              )}
            >
              <div className="flex items-center gap-2">
                <FileText size={14} />
                <span className="text-sm">{file.name}</span>
              </div>
              {files.length > 1 && (
                <button
                  onClick={(e) => handleDeleteFile(e, file.id)}
                  className="opacity-0 group-hover:opacity-100 p-1 hover:bg-gray-700 rounded transition-all"
                  title="Delete File"
                >
                  <Trash2 size={14} />
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};