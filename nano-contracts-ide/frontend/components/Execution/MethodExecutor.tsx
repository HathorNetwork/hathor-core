'use client';

import React, { useState } from 'react';
import { Play, Settings } from 'lucide-react';
import { useIDEStore } from '@/store/ide-store';
import { contractsApi } from '@/lib/api';

interface MethodExecutorProps {
  blueprintId?: string;
}

export const MethodExecutor: React.FC<MethodExecutorProps> = ({ blueprintId }) => {
  const [selectedMethod, setSelectedMethod] = useState('initialize');
  const [parameterValues, setParameterValues] = useState<Record<string, string>>({});
  const [isExecuting, setIsExecuting] = useState(false);
  const [contractId, setContractId] = useState<string | undefined>();
  const { addConsoleMessage } = useIDEStore();

  // Update parameter values when method changes
  const handleMethodChange = (method: string) => {
    setSelectedMethod(method);
    setParameterValues({}); // Clear parameter values when switching methods
  };

  const updateParameterValue = (paramName: string, value: string) => {
    setParameterValues(prev => ({ ...prev, [paramName]: value }));
  };

  // Method definitions with parameter details
  const methodDefinitions = [
    { 
      name: 'initialize', 
      description: 'Initialize the contract', 
      parameters: [
        { name: 'initial_value', type: 'int', description: 'Starting counter value', placeholder: '0' }
      ]
    },
    { 
      name: 'get_count', 
      description: 'Get current counter value', 
      parameters: []
    },
    { 
      name: 'increment', 
      description: 'Increment the counter', 
      parameters: [
        { name: 'amount', type: 'int', description: 'Amount to increment by', placeholder: '1' }
      ]
    },
    { 
      name: 'reset', 
      description: 'Reset counter to zero', 
      parameters: []
    },
  ];

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
          if (!value && param.name !== 'initial_value') {
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
            <input
              type={param.type === 'int' || param.type === 'float' ? 'number' : 'text'}
              value={parameterValues[param.name] || ''}
              onChange={(e) => updateParameterValue(param.name, e.target.value)}
              placeholder={param.placeholder}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
              step={param.type === 'float' ? '0.1' : undefined}
            />
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