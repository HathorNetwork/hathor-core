export interface MethodParameter {
  name: string;
  type: string;
  description?: string;
  placeholder?: string;
}

export interface MethodDefinition {
  name: string;
  description: string;
  parameters: MethodParameter[];
  returnType?: string;
  decorator: 'public' | 'view';
}

/**
 * Parse Python contract code to extract method definitions
 */
export function parseContractMethods(code: string): MethodDefinition[] {
  const methods: MethodDefinition[] = [];
  
  // Split code into lines for analysis
  const lines = code.split('\n');
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    
    // Look for method decorators
    const decoratorMatch = line.match(/^@(public|view)$/);
    if (decoratorMatch && i + 1 < lines.length) {
      const decorator = decoratorMatch[1] as 'public' | 'view';
      const nextLine = lines[i + 1].trim();
      
      // Parse method definition
      const methodMatch = nextLine.match(/^def\s+(\w+)\s*\((.*?)\)\s*(?:->\s*([^:]+))?:/);
      if (methodMatch) {
        const methodName = methodMatch[1];
        const paramsString = methodMatch[2];
        const returnType = methodMatch[3]?.trim();
        
        // Skip if it's a private method (starts with _)
        if (methodName.startsWith('_')) continue;
        
        // Parse parameters
        const parameters = parseMethodParameters(paramsString, decorator);
        
        // Extract docstring as description
        let description = `${decorator === 'view' ? 'View' : 'Public'} method`;
        if (i + 2 < lines.length) {
          const docstringLine = lines[i + 2].trim();
          if (docstringLine.startsWith('"""') || docstringLine.startsWith("'''")) {
            const docstring = docstringLine.replace(/^["']{3}|["']{3}$/g, '').trim();
            if (docstring) {
              description = docstring;
            }
          }
        }
        
        methods.push({
          name: methodName,
          description,
          parameters,
          returnType,
          decorator,
        });
      }
    }
  }
  
  return methods;
}

function parseMethodParameters(paramsString: string, decorator: 'public' | 'view'): MethodParameter[] {
  const parameters: MethodParameter[] = [];
  
  if (!paramsString.trim()) return parameters;
  
  // Split parameters by comma, but handle nested types
  const params = splitParameters(paramsString);
  
  for (const param of params) {
    const trimmed = param.trim();
    
    // Skip 'self' parameter
    if (trimmed === 'self') continue;
    
    // Skip 'ctx: Context' parameter for public methods (it's automatically added)
    if (decorator === 'public' && trimmed.match(/ctx\s*:\s*Context/)) continue;
    
    // Parse parameter with type annotation
    const paramMatch = trimmed.match(/^(\w+)\s*:\s*(.+?)(?:\s*=\s*(.+))?$/);
    if (paramMatch) {
      const name = paramMatch[1];
      let type = paramMatch[2].trim();
      const defaultValue = paramMatch[3]?.trim();
      
      // Map Python types to more user-friendly types with Hathor SDK types
      let mappedType: string;
      
      // Handle Hathor Blueprint SDK types
      if (type === 'Address') {
        mappedType = 'address';
      } else if (type === 'TokenUid') {
        mappedType = 'tokenuid';
      } else if (type === 'ContractId') {
        mappedType = 'contractid';
      } else if (type === 'BlueprintId') {
        mappedType = 'blueprintid';
      } else if (type === 'VertexId') {
        mappedType = 'vertexid';
      } else if (type === 'Amount') {
        mappedType = 'amount';
      } else if (type === 'Timestamp') {
        mappedType = 'timestamp';
      } else if (type === 'TxOutputScript') {
        mappedType = 'hex';
      } else if (type === 'bytes') {
        // For bytes, infer the intent based on parameter name
        const addressPatterns = /^(.*_address|address_.*|caller|owner|recipient|sender|from|to)$/i;
        const tokenPatterns = /^(.*_token|token_.*|.*_uid|uid_.*|token_a|token_b)$/i;
        const contractPatterns = /^(.*_contract|contract_.*|.*_id|id_.*)$/i;
        
        if (addressPatterns.test(name)) {
          mappedType = 'address';
        } else if (tokenPatterns.test(name)) {
          mappedType = 'tokenuid';
        } else if (contractPatterns.test(name)) {
          mappedType = 'contractid';
        } else {
          // For other bytes parameters (data, script, etc.), treat as hex string
          mappedType = 'hex';
        }
      } else {
        const typeMapping: Record<string, string> = {
          'int': 'int',
          'str': 'string',
          'float': 'float',
          'bool': 'boolean',
        };
        mappedType = typeMapping[type] || type;
      }
      
      // Generate description and placeholder based on name and type
      let description = `${name.replace(/_/g, ' ')}`;
      let placeholder = '';
      
      // Handle different Hathor SDK types
      if (mappedType === 'address') {
        description = `Address for ${name.replace(/_/g, ' ')} (20 bytes)`;
        placeholder = 'Select from dropdown';
      } else if (mappedType === 'tokenuid') {
        description = `Token UID for ${name.replace(/_/g, ' ')} (32 bytes)`;
        placeholder = 'Enter token UID (64 hex chars)';
      } else if (mappedType === 'contractid') {
        description = `Contract ID for ${name.replace(/_/g, ' ')} (32 bytes)`;
        placeholder = 'Enter contract ID (64 hex chars)';
      } else if (mappedType === 'blueprintid') {
        description = `Blueprint ID for ${name.replace(/_/g, ' ')} (32 bytes)`;
        placeholder = 'Enter blueprint ID (64 hex chars)';
      } else if (mappedType === 'vertexid') {
        description = `Vertex ID for ${name.replace(/_/g, ' ')} (32 bytes)`;
        placeholder = 'Enter vertex ID (64 hex chars)';
      } else if (mappedType === 'amount') {
        description = `Amount for ${name.replace(/_/g, ' ')} (last 2 digits = decimals)`;
        placeholder = 'Enter amount (e.g., 1025 = 10.25 tokens)';
      } else if (mappedType === 'timestamp') {
        description = `Timestamp for ${name.replace(/_/g, ' ')} (Unix epoch seconds)`;
        placeholder = 'Enter timestamp (e.g., 1578052800)';
      } else if (mappedType === 'hex') {
        description = `${name.replace(/_/g, ' ')} (hex bytes)`;
        placeholder = 'Enter hex string (e.g., deadbeef...)';
      } else if (mappedType === 'int') {
        placeholder = defaultValue || '0';
      } else if (mappedType === 'string') {
        placeholder = defaultValue?.replace(/['"]/g, '') || `Enter ${name}`;
      } else if (mappedType === 'float') {
        placeholder = defaultValue || '0.0';
      } else if (mappedType === 'boolean') {
        placeholder = defaultValue || 'true';
      }
      
      parameters.push({
        name,
        type: mappedType,
        description,
        placeholder,
      });
    }
  }
  
  return parameters;
}

function splitParameters(paramsString: string): string[] {
  const params: string[] = [];
  let current = '';
  let parenDepth = 0;
  let bracketDepth = 0;
  
  for (const char of paramsString) {
    if (char === '(') parenDepth++;
    else if (char === ')') parenDepth--;
    else if (char === '[') bracketDepth++;
    else if (char === ']') bracketDepth--;
    else if (char === ',' && parenDepth === 0 && bracketDepth === 0) {
      params.push(current.trim());
      current = '';
      continue;
    }
    
    current += char;
  }
  
  if (current.trim()) {
    params.push(current.trim());
  }
  
  return params;
}