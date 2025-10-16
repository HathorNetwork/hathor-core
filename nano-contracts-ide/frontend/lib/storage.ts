/**
 * IndexedDB Storage Service for Hathor Nano Contracts IDE
 * Handles persistent storage of files, chat history, and user preferences
 */

export interface StoredFile {
  id: string;
  name: string;
  content: string;
  lastModified: number;
  created: number;
  type: 'contract' | 'other';
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
  originalCode?: string;
  modifiedCode?: string;
  suggestions?: string[];
}

export interface ChatSession {
  id: string;
  messages: ChatMessage[];
  created: number;
  lastModified: number;
  title?: string;
}

class IndexedDBStorage {
  private dbName = 'hathor-nano-contracts-ide';
  private version = 1;
  private db: IDBDatabase | null = null;

  async initialize(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);

      request.onerror = () => reject(new Error('Failed to open IndexedDB'));
      
      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        
        // Files store
        if (!db.objectStoreNames.contains('files')) {
          const filesStore = db.createObjectStore('files', { keyPath: 'id' });
          filesStore.createIndex('name', 'name', { unique: false });
          filesStore.createIndex('lastModified', 'lastModified', { unique: false });
          filesStore.createIndex('type', 'type', { unique: false });
        }

        // Chat sessions store
        if (!db.objectStoreNames.contains('chatSessions')) {
          const chatStore = db.createObjectStore('chatSessions', { keyPath: 'id' });
          chatStore.createIndex('lastModified', 'lastModified', { unique: false });
          chatStore.createIndex('created', 'created', { unique: false });
        }

        // User preferences store
        if (!db.objectStoreNames.contains('preferences')) {
          db.createObjectStore('preferences', { keyPath: 'key' });
        }
      };
    });
  }

  private ensureDB(): IDBDatabase {
    if (!this.db) {
      throw new Error('IndexedDB not initialized. Call initialize() first.');
    }
    return this.db;
  }

  // File Operations
  async saveFile(file: StoredFile): Promise<void> {
    const db = this.ensureDB();
    const transaction = db.transaction(['files'], 'readwrite');
    const store = transaction.objectStore('files');
    
    return new Promise((resolve, reject) => {
      const request = store.put({
        ...file,
        lastModified: Date.now()
      });
      
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error('Failed to save file'));
    });
  }

  async getFile(id: string): Promise<StoredFile | null> {
    const db = this.ensureDB();
    const transaction = db.transaction(['files'], 'readonly');
    const store = transaction.objectStore('files');
    
    return new Promise((resolve, reject) => {
      const request = store.get(id);
      
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(new Error('Failed to get file'));
    });
  }

  async getAllFiles(): Promise<StoredFile[]> {
    const db = this.ensureDB();
    const transaction = db.transaction(['files'], 'readonly');
    const store = transaction.objectStore('files');
    
    return new Promise((resolve, reject) => {
      const request = store.getAll();
      
      request.onsuccess = () => resolve(request.result || []);
      request.onerror = () => reject(new Error('Failed to get files'));
    });
  }

  async deleteFile(id: string): Promise<void> {
    const db = this.ensureDB();
    const transaction = db.transaction(['files'], 'readwrite');
    const store = transaction.objectStore('files');
    
    return new Promise((resolve, reject) => {
      const request = store.delete(id);
      
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error('Failed to delete file'));
    });
  }

  // Chat History Operations
  async saveChatSession(session: ChatSession): Promise<void> {
    const db = this.ensureDB();
    const transaction = db.transaction(['chatSessions'], 'readwrite');
    const store = transaction.objectStore('chatSessions');
    
    return new Promise((resolve, reject) => {
      const request = store.put({
        ...session,
        lastModified: Date.now()
      });
      
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error('Failed to save chat session'));
    });
  }

  async getChatSession(id: string): Promise<ChatSession | null> {
    const db = this.ensureDB();
    const transaction = db.transaction(['chatSessions'], 'readonly');
    const store = transaction.objectStore('chatSessions');
    
    return new Promise((resolve, reject) => {
      const request = store.get(id);
      
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(new Error('Failed to get chat session'));
    });
  }

  async getAllChatSessions(): Promise<ChatSession[]> {
    const db = this.ensureDB();
    const transaction = db.transaction(['chatSessions'], 'readonly');
    const store = transaction.objectStore('chatSessions');
    const index = store.index('lastModified');
    
    return new Promise((resolve, reject) => {
      // Get sessions sorted by lastModified (most recent first)
      const request = index.getAll();
      
      request.onsuccess = () => {
        const sessions = request.result || [];
        sessions.sort((a, b) => b.lastModified - a.lastModified);
        resolve(sessions);
      };
      request.onerror = () => reject(new Error('Failed to get chat sessions'));
    });
  }

  async deleteChatSession(id: string): Promise<void> {
    const db = this.ensureDB();
    const transaction = db.transaction(['chatSessions'], 'readwrite');
    const store = transaction.objectStore('chatSessions');
    
    return new Promise((resolve, reject) => {
      const request = store.delete(id);
      
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error('Failed to delete chat session'));
    });
  }

  // Preferences Operations
  async setPreference(key: string, value: any): Promise<void> {
    const db = this.ensureDB();
    const transaction = db.transaction(['preferences'], 'readwrite');
    const store = transaction.objectStore('preferences');
    
    return new Promise((resolve, reject) => {
      const request = store.put({ key, value, updated: Date.now() });
      
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error('Failed to save preference'));
    });
  }

  async getPreference<T>(key: string, defaultValue: T): Promise<T> {
    const db = this.ensureDB();
    const transaction = db.transaction(['preferences'], 'readonly');
    const store = transaction.objectStore('preferences');
    
    return new Promise((resolve, reject) => {
      const request = store.get(key);
      
      request.onsuccess = () => {
        const result = request.result;
        resolve(result ? result.value : defaultValue);
      };
      request.onerror = () => reject(new Error('Failed to get preference'));
    });
  }

  // Utility Methods
  async clearAllData(): Promise<void> {
    const db = this.ensureDB();
    const transaction = db.transaction(['files', 'chatSessions', 'preferences'], 'readwrite');
    
    return new Promise((resolve, reject) => {
      let completed = 0;
      const stores = ['files', 'chatSessions', 'preferences'];
      
      const checkComplete = () => {
        completed++;
        if (completed === stores.length) {
          resolve();
        }
      };

      stores.forEach(storeName => {
        const request = transaction.objectStore(storeName).clear();
        request.onsuccess = checkComplete;
        request.onerror = () => reject(new Error(`Failed to clear ${storeName}`));
      });
    });
  }

  async getStorageInfo(): Promise<{ files: number; sessions: number; size?: number }> {
    const db = this.ensureDB();
    const transaction = db.transaction(['files', 'chatSessions'], 'readonly');
    
    return new Promise((resolve, reject) => {
      let filesCount = 0;
      let sessionsCount = 0;
      let completed = 0;

      const checkComplete = () => {
        completed++;
        if (completed === 2) {
          resolve({ files: filesCount, sessions: sessionsCount });
        }
      };

      // Count files
      const filesRequest = transaction.objectStore('files').count();
      filesRequest.onsuccess = () => {
        filesCount = filesRequest.result;
        checkComplete();
      };
      filesRequest.onerror = () => reject(new Error('Failed to count files'));

      // Count chat sessions
      const sessionsRequest = transaction.objectStore('chatSessions').count();
      sessionsRequest.onsuccess = () => {
        sessionsCount = sessionsRequest.result;
        checkComplete();
      };
      sessionsRequest.onerror = () => reject(new Error('Failed to count sessions'));
    });
  }
}

// Create singleton instance
export const storage = new IndexedDBStorage();

// Auto-initialize when imported
let initPromise: Promise<void> | null = null;
export const initStorage = () => {
  if (!initPromise) {
    initPromise = storage.initialize();
  }
  return initPromise;
};

// Export types and utilities
export type { StoredFile, ChatMessage, ChatSession };