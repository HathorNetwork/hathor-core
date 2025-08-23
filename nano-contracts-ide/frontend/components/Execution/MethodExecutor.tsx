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

  // Predefined caller addresses for testing (32 bytes = 64 hex characters, all valid hex)
  const callerAddresses = {
    alice: 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd',
    bob: 'b2c3d4e5f67890123456789012345678901234567890123456789012345abcde',
    charlie: 'c3d4e5f678901234567890123456789012345678901234567890123456abcdef',
    owner: 'f0e1d2c3b4a5987654321098765432109876543210987654321098765432',
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
            ) : (
              <input
                type={param.type === 'int' || param.type === 'float' ? 'number' : 'text'}
                value={parameterValues[param.name] || ''}
                onChange={(e) => updateParameterValue(param.name, e.target.value)}
                placeholder={param.placeholder}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                step={param.type === 'float' ? '0.1' : undefined}
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