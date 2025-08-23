import { create } from 'zustand';
import { Contract } from '@/lib/api';
import { storage, initStorage, StoredFile, ChatSession, ChatMessage } from '@/lib/storage';

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
  
  // Chat Sessions
  chatSessions: ChatSession[];
  activeChatSessionId: string | null;
  
  // UI State
  isCompiling: boolean;
  isExecuting: boolean;
  isStorageInitialized: boolean;
  
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
  
  // Chat session actions
  createChatSession: () => string;
  addChatMessage: (sessionId: string, message: ChatMessage) => void;
  getChatSession: (id: string) => ChatSession | null;
  setActiveChatSession: (id: string) => void;
  deleteChatSession: (id: string) => void;
  
  // Storage operations
  initializeStore: () => Promise<void>;
  loadFilesFromStorage: () => Promise<void>;
  saveFileToStorage: (file: File) => Promise<void>;
  deleteFileFromStorage: (id: string) => Promise<void>;
  loadChatSessionsFromStorage: () => Promise<void>;
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
    {
      id: '2',
      name: 'LiquidityPool.py',
      content: `"""
Liquidity Pool Contract - Demonstrates Hathor Blueprint SDK types and patterns
A simple DEX liquidity pool for token swapping with proper Hathor constraints
"""
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import public, view, TokenUid, Address, Amount


class LiquidityPool(Blueprint):
    """
    A simple liquidity pool contract for two tokens
    Demonstrates proper use of Hathor Blueprint SDK types
    """
    
    # Contract state - all fields must be initialized in initialize()
    token_a: TokenUid
    token_b: TokenUid
    owner: Address
    fee_rate: int
    total_liquidity: Amount
    
    @public
    def initialize(self, ctx: Context, token_a: TokenUid, token_b: TokenUid, fee_rate: int) -> None:
        """Initialize the liquidity pool contract"""
        self.token_a = token_a
        self.token_b = token_b
        self.owner = ctx.vertex.hash
        self.fee_rate = fee_rate  # Fee in basis points (e.g., 30 = 0.3%)
        self.total_liquidity = 0
    
    @view
    def get_tokens(self) -> tuple[TokenUid, TokenUid]:
        """Get the two tokens in this pool"""
        return (self.token_a, self.token_b)
    
    @view
    def get_owner(self) -> Address:
        """Get contract owner address"""
        return self.owner
    
    @view
    def get_fee_rate(self) -> int:
        """Get fee rate in basis points"""
        return self.fee_rate
    
    @view
    def get_total_liquidity(self) -> Amount:
        """Get total liquidity in the pool"""
        return self.total_liquidity
    
    @view
    def get_pool_info(self) -> dict[str, str]:
        """Get pool information"""
        return {
            "token_a": self.token_a.hex(),
            "token_b": self.token_b.hex(),
            "owner": self.owner.hex(),
            "fee_rate": str(self.fee_rate),
            "total_liquidity": str(self.total_liquidity)
        }
    
    @public
    def set_fee_rate(self, ctx: Context, new_fee_rate: int) -> None:
        """Set new fee rate (only owner)"""
        if ctx.vertex.hash != self.owner:
            raise ValueError("Only owner can set fee rate")
        
        if new_fee_rate < 0 or new_fee_rate > 1000:  # Max 10%
            raise ValueError("Fee rate must be between 0 and 1000 basis points")
        
        self.fee_rate = new_fee_rate
    
    @public
    def add_liquidity(self, ctx: Context, amount: Amount) -> None:
        """Add liquidity to the pool (simplified version)"""
        if amount <= 0:
            raise ValueError("Amount must be positive")
        
        # This is a simplified version - in a real DEX you'd handle
        # token deposits via actions and calculate LP tokens
        self.total_liquidity += amount
    
    @view
    def calculate_swap_output(self, input_amount: Amount, input_token: TokenUid) -> Amount:
        """Calculate output amount for a swap (simplified)"""
        if input_token != self.token_a and input_token != self.token_b:
            raise ValueError("Invalid input token")
        
        if input_amount <= 0:
            raise ValueError("Input amount must be positive")
        
        # Simplified calculation - real DEX would use constant product formula
        fee = (input_amount * self.fee_rate) // 10000
        output_amount = input_amount - fee
        
        return output_amount


# This is the blueprint that will be deployed
__blueprint__ = LiquidityPool`,
      language: 'python',
      path: '/contracts/LiquidityPool.py',
    },
  ],
  activeFileId: '1',
  
  consoleMessages: [],
  compiledContracts: [],
  
  chatSessions: [],
  activeChatSessionId: null,
  
  isCompiling: false,
  isExecuting: false,
  isStorageInitialized: false,
  
  // Actions
  addFile: (file) => {
    set((state) => ({
      files: [...state.files, file],
      activeFileId: file.id,
    }));
    // Auto-persist to storage
    const state = useIDEStore.getState();
    if (state.isStorageInitialized) {
      state.saveFileToStorage(file).catch(console.error);
    }
  },
  
  updateFile: (id, content) => {
    set((state) => ({
      files: state.files.map((f) =>
        f.id === id ? { ...f, content } : f
      ),
    }));
    // Auto-persist to storage
    const state = useIDEStore.getState();
    if (state.isStorageInitialized) {
      const updatedFile = state.files.find(f => f.id === id);
      if (updatedFile) {
        state.saveFileToStorage(updatedFile).catch(console.error);
      }
    }
  },
  
  deleteFile: (id) => {
    set((state) => ({
      files: state.files.filter((f) => f.id !== id),
      activeFileId:
        state.activeFileId === id
          ? state.files[0]?.id || null
          : state.activeFileId,
    }));
    // Delete from storage
    const state = useIDEStore.getState();
    if (state.isStorageInitialized) {
      state.deleteFileFromStorage(id).catch(console.error);
    }
  },
  
  setActiveFile: (id) => {
    set(() => ({
      activeFileId: id,
    }));
    // Save active file preference
    const state = useIDEStore.getState();
    if (state.isStorageInitialized) {
      storage.setPreference('lastActiveFileId', id).catch(console.error);
    }
  },
  
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
  
  // Chat session actions
  createChatSession: () => {
    const sessionId = Date.now().toString();
    const newSession: ChatSession = {
      id: sessionId,
      messages: [],
      created: Date.now(),
      lastModified: Date.now(),
      title: 'New Chat Session'
    };
    
    set((state) => ({
      chatSessions: [...state.chatSessions, newSession],
      activeChatSessionId: sessionId,
    }));
    
    // Save to storage
    const state = useIDEStore.getState();
    if (state.isStorageInitialized) {
      storage.saveChatSession(newSession).catch(console.error);
    }
    
    return sessionId;
  },

  addChatMessage: (sessionId, message) => {
    set((state) => ({
      chatSessions: state.chatSessions.map(session =>
        session.id === sessionId
          ? {
              ...session,
              messages: [...session.messages, message],
              lastModified: Date.now(),
            }
          : session
      ),
    }));
    
    // Save to storage
    const state = useIDEStore.getState();
    if (state.isStorageInitialized) {
      const updatedSession = state.chatSessions.find(s => s.id === sessionId);
      if (updatedSession) {
        storage.saveChatSession(updatedSession).catch(console.error);
      }
    }
  },

  getChatSession: (id) => {
    const state = useIDEStore.getState();
    return state.chatSessions.find(session => session.id === id) || null;
  },

  setActiveChatSession: (id) => {
    set(() => ({
      activeChatSessionId: id,
    }));
    
    // Save active session preference
    const state = useIDEStore.getState();
    if (state.isStorageInitialized) {
      storage.setPreference('activeChatSessionId', id).catch(console.error);
    }
  },

  deleteChatSession: (id) => {
    set((state) => ({
      chatSessions: state.chatSessions.filter(session => session.id !== id),
      activeChatSessionId: state.activeChatSessionId === id ? null : state.activeChatSessionId,
    }));
    
    // Delete from storage
    const state = useIDEStore.getState();
    if (state.isStorageInitialized) {
      storage.deleteChatSession(id).catch(console.error);
    }
  },
  
  // Storage operations
  initializeStore: async () => {
    try {
      await initStorage();
      set({ isStorageInitialized: true });
      
      // Load files from storage
      const state = useIDEStore.getState();
      await state.loadFilesFromStorage();
      await state.loadChatSessionsFromStorage();
      
      console.log('IDE store initialized with persistent storage');
    } catch (error) {
      console.error('Failed to initialize storage:', error);
      // Continue with default files if storage fails
      set({ isStorageInitialized: false });
    }
  },
  
  loadFilesFromStorage: async () => {
    try {
      const storedFiles = await storage.getAllFiles();
      
      if (storedFiles.length > 0) {
        // Convert StoredFile to File format
        const files: File[] = storedFiles.map(stored => ({
          id: stored.id,
          name: stored.name,
          content: stored.content,
          language: stored.name.endsWith('.py') ? 'python' : 'text',
          path: `/contracts/${stored.name}`,
        }));
        
        // Get last active file ID from preferences
        const lastActiveFileId = await storage.getPreference('lastActiveFileId', files[0]?.id || null);
        const validActiveFileId = files.find(f => f.id === lastActiveFileId)?.id || files[0]?.id || null;
        
        set({
          files,
          activeFileId: validActiveFileId,
        });
        
        console.log(`Loaded ${files.length} files from storage`);
      } else {
        // First time - save default files to storage
        const state = useIDEStore.getState();
        for (const file of state.files) {
          await state.saveFileToStorage(file);
        }
        console.log('Saved default files to storage');
      }
    } catch (error) {
      console.error('Failed to load files from storage:', error);
    }
  },
  
  saveFileToStorage: async (file: File) => {
    try {
      const storedFile: StoredFile = {
        id: file.id,
        name: file.name,
        content: file.content,
        lastModified: Date.now(),
        created: Date.now(), // This should ideally come from existing stored file
        type: file.name.endsWith('.py') ? 'contract' : 'other',
      };
      
      // Check if file exists to preserve created date
      const existingFile = await storage.getFile(file.id);
      if (existingFile) {
        storedFile.created = existingFile.created;
      }
      
      await storage.saveFile(storedFile);
    } catch (error) {
      console.error('Failed to save file to storage:', error);
    }
  },
  
  deleteFileFromStorage: async (id: string) => {
    try {
      await storage.deleteFile(id);
    } catch (error) {
      console.error('Failed to delete file from storage:', error);
    }
  },

  loadChatSessionsFromStorage: async () => {
    try {
      const storedSessions = await storage.getAllChatSessions();
      
      if (storedSessions.length > 0) {
        // Get active session ID from preferences
        const activeSessionId = await storage.getPreference('activeChatSessionId', null);
        const validActiveSessionId = storedSessions.find(s => s.id === activeSessionId)?.id || null;
        
        set({
          chatSessions: storedSessions,
          activeChatSessionId: validActiveSessionId,
        });
        
        console.log(`Loaded ${storedSessions.length} chat sessions from storage`);
      } else {
        console.log('No chat sessions found in storage');
      }
    } catch (error) {
      console.error('Failed to load chat sessions from storage:', error);
    }
  },
}));