'use client';

import React, { useState, useEffect, useMemo } from 'react';
import { Play, Settings } from 'lucide-react';
import { useIDEStore } from '@/store/ide-store';
import { contractsApi } from '@/lib/api';
import { parseContractMethods, MethodDefinition } from '@/utils/contractParser';

interface MethodExecutorProps {
  blueprintId?: string;
}

export const MethodExecutor: React.FC<MethodExecutorProps> = ({ blueprintId }) => {
  const [selectedMethod, setSelectedMethod] = useState('');
  const [parameterValues, setParameterValues] = useState<Record<string, string>>({});
  const [isExecuting, setIsExecuting] = useState(false);
  const [contractId, setContractId] = useState<string | undefined>();
  const [selectedCaller, setSelectedCaller] = useState<string>('alice');
  const { addConsoleMessage, files, activeFileId } = useIDEStore();

  // Get current file content to parse methods
  const activeFile = files.find(f => f.id === activeFileId);
  
  // Parse methods from current file
  const methodDefinitions = useMemo(() => {
    if (!activeFile?.content) return [];
    return parseContractMethods(activeFile.content);
  }, [activeFile?.content]);

  // Set default method when methods are loaded
  useEffect(() => {
    if (methodDefinitions.length > 0 && !selectedMethod) {
      // Try to find 'initialize' method first, otherwise use the first method
      const initMethod = methodDefinitions.find(m => m.name === 'initialize');
      setSelectedMethod(initMethod ? initMethod.name : methodDefinitions[0].name);
    }
  }, [methodDefinitions, selectedMethod]);

  // Update parameter values when method changes
  const handleMethodChange = (method: string) => {
    setSelectedMethod(method);
    setParameterValues({}); // Clear parameter values when switching methods
  };

  const updateParameterValue = (paramName: string, value: string) => {
    setParameterValues(prev => ({ ...prev, [paramName]: value }));
  };

  // Predefined caller addresses for testing (20 bytes = 40 hex characters, all valid hex)
  const callerAddresses = {
    alice: 'a1b2c3d4e5f6789012345678901234567890abcd',
    bob: 'b2c3d4e5f67890123456789012345678901abcde',
    charlie: 'c3d4e5f678901234567890123456789012abcdef',
    owner: 'f0e1d2c3b4a59876543210987654321098765432',
  };

  // Predefined sample values for different Hathor SDK types
  const sampleValues = {
    tokenuid: {
      htr: '0000000000000000000000000000000000000000000000000000000000000000',
      token_a: '00000943573723a28e3dd980c10e08419d0e00bc647a95f4ca9671ebea7d5669',
      token_b: '000002d4c7e859c6b1ba1bb2a3d59bb1e2d0ff3bb9a5b3b4b5f5e3c9d8e8c9bb',
    },
    contractid: {
      contract_1: '000063f99b133c7630bc9d0117919f5b8726155412ad063dbbd618bdc7f85d7a',
      contract_2: '0001b8c4e2d1c3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8',
    },
    blueprintid: {
      blueprint_1: '3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595',
      blueprint_2: '4dc143711cef8ec895911f5fb822c21787fa3f78502f93cc73739d345f882606',
    },
  };


  const handleExecute = async () => {
    if (!blueprintId) {
      addConsoleMessage('error', 'No compiled contract available. Please compile first.');
      return;
    }

    // For initialize, use blueprint ID. For other methods, use contract ID
    const targetId = selectedMethod === 'initialize' ? blueprintId : contractId;
    
    if (selectedMethod !== 'initialize' && !contractId) {
      addConsoleMessage('error', 'Please initialize the contract first before calling other methods.');
      return;
    }

    setIsExecuting(true);
    addConsoleMessage('info', `Calling method: ${selectedMethod}...`);

    try {
      // Get current method definition
      const currentMethod = methodDefinitions.find(m => m.name === selectedMethod);
      
      // Prepare arguments from parameter values
      let args: any[] = [];
      if (currentMethod?.parameters && currentMethod.parameters.length > 0) {
        args = currentMethod.parameters.map(param => {
          const value = parameterValues[param.name] || '';
          if (!value && param.name !== 'initial_value' && param.name !== 'initial_supply') {
            throw new Error(`Missing required parameter: ${param.name}`);
          }
          if (param.type === 'int') {
            const numValue = parseInt(value || '0');
            if (isNaN(numValue)) {
              throw new Error(`Invalid integer value for ${param.name}: ${value}`);
            }
            return numValue;
          } else if (param.type === 'float') {
            const floatValue = parseFloat(value || '0');
            if (isNaN(floatValue)) {
              throw new Error(`Invalid float value for ${param.name}: ${value}`);
            }
            return floatValue;
          } else if (param.type === 'address') {
            // Convert address selection to hex string (backend will convert to bytes)
            if (value in callerAddresses) {
              return callerAddresses[value as keyof typeof callerAddresses];
            }
            return value; // Return as-is if not a predefined address
          } else if (param.type === 'tokenuid' || param.type === 'contractid' || param.type === 'blueprintid' || param.type === 'vertexid') {
            // For Hathor SDK ID types, validate hex string (32 bytes = 64 hex chars)
            // If it's a predefined value from dropdown, it's already valid
            const finalValue = value || '';
            if (finalValue && (!/^[0-9a-fA-F]{64}$/.test(finalValue))) {
              throw new Error(`Invalid ${param.type} for ${param.name}: ${finalValue}. Must be 64 hex characters (32 bytes).`);
            }
            return finalValue;
          } else if (param.type === 'amount') {
            // For Amount type, validate integer
            const amountValue = parseInt(value || '0');
            if (isNaN(amountValue) || amountValue < 0) {
              throw new Error(`Invalid amount for ${param.name}: ${value}. Must be a non-negative integer where last 2 digits are decimals.`);
            }
            return amountValue;
          } else if (param.type === 'timestamp') {
            // For Timestamp type, validate Unix epoch seconds
            const timestampValue = parseInt(value || '0');
            if (isNaN(timestampValue) || timestampValue < 0) {
              throw new Error(`Invalid timestamp for ${param.name}: ${value}. Must be a non-negative integer (Unix epoch seconds).`);
            }
            return timestampValue;
          } else if (param.type === 'hex') {
            // For hex parameters, ensure it's a valid hex string and return as-is
            // Backend will convert to bytes
            if (value && !/^[0-9a-fA-F]*$/.test(value)) {
              throw new Error(`Invalid hex value for ${param.name}: ${value}. Use only 0-9 and a-f characters.`);
            }
            return value;
          } else {
            return value; // string or other types
          }
        });
      }

      const result = await contractsApi.execute({
        contract_id: targetId!,
        method_name: selectedMethod,
        args,
        kwargs: {},
        caller_address: callerAddresses[selectedCaller as keyof typeof callerAddresses],
        method_type: currentMethod?.decorator,
      });

      if (result.success) {
        addConsoleMessage('success', `✅ Method '${selectedMethod}' executed successfully`);
        
        // If this was initialize, capture the contract ID
        if (selectedMethod === 'initialize' && result.result && typeof result.result === 'object' && 'contract_id' in result.result) {
          const newContractId = (result.result as any).contract_id;
          setContractId(newContractId);
          addConsoleMessage('info', `Contract created with ID: ${newContractId}`);
        } else if (result.result !== undefined && result.result !== null) {
          addConsoleMessage('info', `Result: ${JSON.stringify(result.result)}`);
        } else {
          addConsoleMessage('info', 'Method completed (no return value)');
        }
        
        if (result.gas_used) {
          addConsoleMessage('info', `Gas used: ${result.gas_used}`);
        }
      } else {
        addConsoleMessage('error', `Method execution failed: ${result.error}`);
      }
    } catch (error: any) {
      addConsoleMessage('error', `Execution error: ${error.message || error}`);
    } finally {
      setIsExecuting(false);
    }
  };

  if (!blueprintId) {
    return (
      <div className="h-full bg-gray-800 border-r border-gray-700 p-4 flex items-center justify-center">
        <div className="text-gray-400 text-center">
          <Settings className="mx-auto mb-2" size={20} />
          <p className="text-sm">Compile a contract first to execute methods</p>
        </div>
      </div>
    );
  }

  if (methodDefinitions.length === 0) {
    return (
      <div className="h-full bg-gray-800 border-r border-gray-700 p-4 flex items-center justify-center">
        <div className="text-gray-400 text-center">
          <Settings className="mx-auto mb-2" size={20} />
          <p className="text-sm">No methods found in contract</p>
          <p className="text-xs mt-1">Make sure your contract has @public or @view decorated methods</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full bg-gray-800 border-r border-gray-700 p-4 overflow-y-auto">
      <div className="flex flex-col gap-4">
        <h3 className="text-lg font-semibold text-white mb-2">Contract Methods</h3>
        {contractId && (
          <div className="bg-green-900/30 border border-green-700 rounded p-2 text-sm">
            <span className="text-green-400">✅ Contract Initialized</span>
            <div className="text-green-300 text-xs mt-1">
              ID: {contractId.slice(0, 16)}...
            </div>
          </div>
        )}
        
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Caller Address:
          </label>
          <select
            value={selectedCaller}
            onChange={(e) => setSelectedCaller(e.target.value)}
            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500 mb-2"
          >
            {Object.keys(callerAddresses).map((name) => (
              <option key={name} value={name}>
                {name} ({callerAddresses[name as keyof typeof callerAddresses].slice(0, 8)}...)
              </option>
            ))}
          </select>
          <div className="text-xs text-gray-400 mb-4">
            Full: {callerAddresses[selectedCaller as keyof typeof callerAddresses]}
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Method to Execute:
          </label>
          <select
            value={selectedMethod}
            onChange={(e) => handleMethodChange(e.target.value)}
            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500"
          >
            {methodDefinitions.map((method) => (
              <option key={method.name} value={method.name}>
                {method.name} - {method.description}
              </option>
            ))}
          </select>
        </div>

        {/* Parameter inputs */}
        {methodDefinitions.find(m => m.name === selectedMethod)?.parameters.map((param) => (
          <div key={param.name}>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              {param.name} ({param.type})
              <span className="text-gray-400 text-xs ml-1">- {param.description}</span>
            </label>
            {param.type === 'address' ? (
              <select
                value={parameterValues[param.name] || ''}
                onChange={(e) => updateParameterValue(param.name, e.target.value)}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500"
              >
                <option value="">Select address...</option>
                {Object.keys(callerAddresses).map((name) => (
                  <option key={name} value={name}>
                    {name} ({callerAddresses[name as keyof typeof callerAddresses].slice(0, 8)}...)
                  </option>
                ))}
              </select>
            ) : param.type === 'tokenuid' ? (
              <div className="space-y-2">
                <select
                  value={parameterValues[param.name] || ''}
                  onChange={(e) => updateParameterValue(param.name, e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="">Select token UID or enter custom...</option>
                  {Object.entries(sampleValues.tokenuid).map(([name, uid]) => (
                    <option key={name} value={uid}>
                      {name.toUpperCase()} ({uid.slice(0, 8)}...)
                    </option>
                  ))}
                </select>
                <input
                  type="text"
                  value={parameterValues[param.name] || ''}
                  onChange={(e) => updateParameterValue(param.name, e.target.value)}
                  placeholder={param.placeholder}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                  maxLength={64}
                  pattern="[0-9a-fA-F]{64}"
                  title="Enter exactly 64 hexadecimal characters (0-9, a-f, A-F)"
                />
              </div>
            ) : param.type === 'contractid' ? (
              <div className="space-y-2">
                <select
                  value={parameterValues[param.name] || ''}
                  onChange={(e) => updateParameterValue(param.name, e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="">Select contract ID or enter custom...</option>
                  {Object.entries(sampleValues.contractid).map(([name, id]) => (
                    <option key={name} value={id}>
                      {name.replace('_', ' ').toUpperCase()} ({id.slice(0, 8)}...)
                    </option>
                  ))}
                </select>
                <input
                  type="text"
                  value={parameterValues[param.name] || ''}
                  onChange={(e) => updateParameterValue(param.name, e.target.value)}
                  placeholder={param.placeholder}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                  maxLength={64}
                  pattern="[0-9a-fA-F]{64}"
                  title="Enter exactly 64 hexadecimal characters (0-9, a-f, A-F)"
                />
              </div>
            ) : param.type === 'blueprintid' ? (
              <div className="space-y-2">
                <select
                  value={parameterValues[param.name] || ''}
                  onChange={(e) => updateParameterValue(param.name, e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="">Select blueprint ID or enter custom...</option>
                  {Object.entries(sampleValues.blueprintid).map(([name, id]) => (
                    <option key={name} value={id}>
                      {name.replace('_', ' ').toUpperCase()} ({id.slice(0, 8)}...)
                    </option>
                  ))}
                </select>
                <input
                  type="text"
                  value={parameterValues[param.name] || ''}
                  onChange={(e) => updateParameterValue(param.name, e.target.value)}
                  placeholder={param.placeholder}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                  maxLength={64}
                  pattern="[0-9a-fA-F]{64}"
                  title="Enter exactly 64 hexadecimal characters (0-9, a-f, A-F)"
                />
              </div>
            ) : (
              <input
                type={
                  param.type === 'int' || param.type === 'amount' || param.type === 'timestamp' 
                    ? 'number' 
                    : param.type === 'float' 
                      ? 'number' 
                      : 'text'
                }
                value={parameterValues[param.name] || ''}
                onChange={(e) => updateParameterValue(param.name, e.target.value)}
                placeholder={param.placeholder}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                step={param.type === 'float' ? '0.1' : param.type === 'amount' || param.type === 'timestamp' ? '1' : undefined}
                min={param.type === 'amount' || param.type === 'timestamp' ? '0' : undefined}
                maxLength={
                  param.type === 'tokenuid' || param.type === 'contractid' || param.type === 'blueprintid' || param.type === 'vertexid' 
                    ? 64 
                    : undefined
                }
                pattern={
                  param.type === 'tokenuid' || param.type === 'contractid' || param.type === 'blueprintid' || param.type === 'vertexid' 
                    ? '[0-9a-fA-F]{64}' 
                    : param.type === 'hex'
                      ? '[0-9a-fA-F]*'
                      : undefined
                }
                title={
                  param.type === 'tokenuid' || param.type === 'contractid' || param.type === 'blueprintid' || param.type === 'vertexid' 
                    ? 'Enter exactly 64 hexadecimal characters (0-9, a-f, A-F)'
                    : param.type === 'hex'
                      ? 'Enter hexadecimal characters (0-9, a-f, A-F)'
                      : param.type === 'amount'
                        ? 'Enter amount where last 2 digits represent decimals (e.g., 1025 = 10.25 tokens)'
                        : param.type === 'timestamp'
                          ? 'Enter Unix timestamp in seconds'
                          : undefined
                }
              />
            )}
          </div>
        ))}

        <button
          onClick={handleExecute}
          disabled={isExecuting}
          className={`flex items-center justify-center gap-2 px-4 py-2 rounded font-medium transition-colors ${
            isExecuting
              ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
              : 'bg-green-600 text-white hover:bg-green-700'
          }`}
        >
          <Play size={16} />
          {isExecuting ? 'Executing...' : `Execute ${selectedMethod}`}
        </button>
      </div>
    </div>
  );
};