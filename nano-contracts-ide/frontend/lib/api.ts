import axios from 'axios';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export interface CompileRequest {
  code: string;
  blueprint_name?: string;
}

export interface CompileResponse {
  success: boolean;
  blueprint_id?: string;
  errors: string[];
  warnings: string[];
  gas_estimate?: number;
}

export interface ValidationRequest {
  code: string;
  strict?: boolean;
}

export interface ValidationResponse {
  valid: boolean;
  errors: Array<{
    line: number;
    column: number;
    message: string;
    severity: string;
    rule: string;
  }>;
  suggestions: string[];
}

export interface ExecuteRequest {
  contract_id: string;
  method_name: string;
  args?: any[];
  kwargs?: Record<string, any>;
  actions?: Array<Record<string, any>>;
  context?: Record<string, any>;
  caller_address?: string;
}

export interface ExecuteResponse {
  success: boolean;
  result?: any;
  error?: string;
  gas_used?: number;
  logs: string[];
  state_changes: Record<string, any>;
}

export interface Contract {
  contract_id: string;
  blueprint_id: string;
  code: string;
  methods: string[];
  created_at: string;
}

export interface StorageInfo {
  type: string;
  contracts_count: number;
  total_size: number;
}

export const contractsApi = {
  compile: async (request: CompileRequest): Promise<CompileResponse> => {
    const response = await api.post('/api/contracts/compile', request);
    return response.data;
  },

  execute: async (request: ExecuteRequest): Promise<ExecuteResponse> => {
    const response = await api.post('/api/contracts/execute', request);
    return response.data;
  },

  list: async (): Promise<Contract[]> => {
    const response = await api.get('/api/contracts/list');
    return response.data;
  },

  get: async (contractId: string): Promise<Contract> => {
    const response = await api.get(`/api/contracts/${contractId}`);
    return response.data;
  },

  getMethods: async (contractId: string): Promise<any[]> => {
    const response = await api.get(`/api/contracts/${contractId}/methods`);
    return response.data;
  },

  getState: async (contractId: string): Promise<Record<string, any>> => {
    const response = await api.get(`/api/contracts/${contractId}/state`);
    return response.data;
  },
};

export const validationApi = {
  validate: async (request: ValidationRequest): Promise<ValidationResponse> => {
    const response = await api.post('/api/validation/validate', request);
    return response.data;
  },

  getRules: async (): Promise<any[]> => {
    const response = await api.get('/api/validation/rules');
    return response.data.rules;
  },
};

export const storageApi = {
  getInfo: async (): Promise<StorageInfo> => {
    const response = await api.get('/api/storage/info');
    return response.data;
  },

  reset: async (): Promise<void> => {
    await api.post('/api/storage/reset');
  },
};

export interface ChatRequest {
  message: string;
  current_file_content?: string;
  current_file_name?: string;
  console_messages?: string[];
  context?: Record<string, any>;
}

export interface ChatResponse {
  success: boolean;
  message: string;
  error?: string;
  suggestions?: string[];
}

export const aiApi = {
  chat: async (request: ChatRequest): Promise<ChatResponse> => {
    const response = await api.post('/api/ai/chat', request);
    return response.data;
  },

  getSuggestions: async (): Promise<{ suggestions: string[] }> => {
    const response = await api.get('/api/ai/suggestions');
    return response.data;
  },

  getExamples: async (): Promise<{ examples: any[] }> => {
    const response = await api.get('/api/ai/examples');
    return response.data;
  },
};

export const healthApi = {
  check: async (): Promise<{ status: string }> => {
    const response = await api.get('/health');
    return response.data;
  },
};

export default api;