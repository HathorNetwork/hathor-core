import { create } from 'zustand';
import { Contract } from '@/lib/api';

export interface File {
  id: string;
  name: string;
  content: string;
  language: string;
  path: string;
}

export interface ConsoleMessage {
  id: string;
  type: 'info' | 'error' | 'warning' | 'success';
  message: string;
  timestamp: Date;
}

interface IDEState {
  // Files
  files: File[];
  activeFileId: string | null;
  
  // Console
  consoleMessages: ConsoleMessage[];
  
  // Contracts
  compiledContracts: Contract[];
  
  // UI State
  isCompiling: boolean;
  isExecuting: boolean;
  
  // Actions
  addFile: (file: File) => void;
  updateFile: (id: string, content: string) => void;
  deleteFile: (id: string) => void;
  setActiveFile: (id: string) => void;
  
  addConsoleMessage: (type: ConsoleMessage['type'], message: string) => void;
  clearConsole: () => void;
  
  addCompiledContract: (contract: Contract) => void;
  
  setIsCompiling: (value: boolean) => void;
  setIsExecuting: (value: boolean) => void;
}

export const useIDEStore = create<IDEState>((set) => ({
  // Initial state
  files: [
    {
      id: '1',
      name: 'SimpleCounter.py',
      content: `from hathor.nanocontracts import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import public, view

class SimpleCounter(Blueprint):
    """A simple counter that can be incremented and read"""
    
    # Contract state
    count: int
    
    @public
    def initialize(self, ctx: Context) -> None:
        """Initialize the counter"""
        self.count = 0
    
    @public
    def increment(self, ctx: Context, amount: int) -> None:
        """Increment the counter by the specified amount"""
        if amount <= 0:
            raise ValueError("Amount must be positive")
        
        self.count += amount
    
    @view
    def get_count(self) -> int:
        """Get the current counter value"""
        return self.count
    
    @public
    def reset(self, ctx: Context) -> None:
        """Reset the counter to zero"""
        self.count = 0

__blueprint__ = SimpleCounter`,
      language: 'python',
      path: '/contracts/SimpleCounter.py',
    },
  ],
  activeFileId: '1',
  
  consoleMessages: [],
  compiledContracts: [],
  
  isCompiling: false,
  isExecuting: false,
  
  // Actions
  addFile: (file) =>
    set((state) => ({
      files: [...state.files, file],
      activeFileId: file.id,
    })),
  
  updateFile: (id, content) =>
    set((state) => ({
      files: state.files.map((f) =>
        f.id === id ? { ...f, content } : f
      ),
    })),
  
  deleteFile: (id) =>
    set((state) => ({
      files: state.files.filter((f) => f.id !== id),
      activeFileId:
        state.activeFileId === id
          ? state.files[0]?.id || null
          : state.activeFileId,
    })),
  
  setActiveFile: (id) =>
    set(() => ({
      activeFileId: id,
    })),
  
  addConsoleMessage: (type, message) =>
    set((state) => ({
      consoleMessages: [
        ...state.consoleMessages,
        {
          id: Date.now().toString(),
          type,
          message,
          timestamp: new Date(),
        },
      ],
    })),
  
  clearConsole: () =>
    set(() => ({
      consoleMessages: [],
    })),
  
  addCompiledContract: (contract) =>
    set((state) => ({
      compiledContracts: [...state.compiledContracts, contract],
    })),
  
  setIsCompiling: (value) =>
    set(() => ({
      isCompiling: value,
    })),
  
  setIsExecuting: (value) =>
    set(() => ({
      isExecuting: value,
    })),
}));