'use client';

import React from 'react';
import { Panel, PanelGroup, PanelResizeHandle, ImperativePanelHandle } from 'react-resizable-panels';
import { FileExplorer } from './FileExplorer/FileExplorer';
import { CodeEditor } from './Editor/CodeEditor';
import { Console } from './Console/Console';
import { Toolbar } from './Toolbar/Toolbar';
import { MethodExecutor } from './Execution/MethodExecutor';
import { AIAssistant } from './AI/AIAssistant';
import { useIDEStore } from '@/store/ide-store';
import { contractsApi, validationApi } from '@/lib/api';

export function IDE() {
  const [currentBlueprintId, setCurrentBlueprintId] = React.useState<string | undefined>();
  const [isAICollapsed, setIsAICollapsed] = React.useState(false);
  const aiPanelRef = React.useRef<ImperativePanelHandle>(null);
  const codePanelRef = React.useRef<ImperativePanelHandle>(null);
  
  const {
    files,
    activeFileId,
    addConsoleMessage,
    setIsCompiling,
    setIsExecuting,
    isCompiling,
    isExecuting,
    addCompiledContract,
    initializeStore,
  } = useIDEStore();

  // Initialize storage on component mount
  React.useEffect(() => {
    initializeStore();
  }, [initializeStore]);

  const activeFile = files.find((f) => f.id === activeFileId);

  const handleCompile = async () => {
    if (!activeFile) return;

    setIsCompiling(true);
    addConsoleMessage('info', `Compiling ${activeFile.name}...`);

    try {
      // First validate the code
      const validationResult = await validationApi.validate({
        code: activeFile.content,
        strict: true,
      });

      // Log validation warnings/errors
      validationResult.errors.forEach((error) => {
        if (error.severity === 'error') {
          addConsoleMessage('error', `Line ${error.line}: ${error.message}`);
        } else {
          addConsoleMessage('warning', `Line ${error.line}: ${error.message}`);
        }
      });

      if (!validationResult.valid && validationResult.errors.some(e => e.severity === 'error')) {
        addConsoleMessage('error', 'Compilation failed due to validation errors');
        return;
      }

      // Compile the contract
      const result = await contractsApi.compile({
        code: activeFile.content,
        blueprint_name: activeFile.name.replace('.py', ''),
      });

      if (result.success) {
        addConsoleMessage('success', `✅ Successfully compiled ${activeFile.name}`);
        if (result.blueprint_id) {
          addConsoleMessage('info', `Blueprint ID: ${result.blueprint_id}`);
        }
        if (result.gas_estimate) {
          addConsoleMessage('info', `Estimated gas: ${result.gas_estimate}`);
        }

        // Add to compiled contracts and set current blueprint
        if (result.blueprint_id) {
          setCurrentBlueprintId(result.blueprint_id);
          addCompiledContract({
            contract_id: result.blueprint_id,
            blueprint_id: result.blueprint_id,
            code: activeFile.content,
            methods: [],
            created_at: new Date().toISOString(),
          });
        }
      } else {
        addConsoleMessage('error', 'Compilation failed');
        result.errors.forEach((error) => {
          addConsoleMessage('error', error);
        });
      }

      result.warnings.forEach((warning) => {
        addConsoleMessage('warning', warning);
      });
    } catch (error: any) {
      addConsoleMessage('error', `Compilation error: ${error.message || error}`);
    } finally {
      setIsCompiling(false);
    }
  };

  const handleExecute = async () => {
    if (!activeFile) return;

    setIsExecuting(true);
    addConsoleMessage('info', `Executing ${activeFile.name}...`);

    try {
      // For now, just compile and create a contract instance
      const compileResult = await contractsApi.compile({
        code: activeFile.content,
        blueprint_name: activeFile.name.replace('.py', ''),
      });

      if (compileResult.success && compileResult.blueprint_id) {
        // Try to execute the initialize method
        const executeResult = await contractsApi.execute({
          contract_id: compileResult.blueprint_id,
          method_name: 'initialize',
          args: [],
          kwargs: {},
        });

        if (executeResult.success) {
          addConsoleMessage('success', '✅ Contract executed successfully');
          if (executeResult.result !== undefined) {
            addConsoleMessage('info', `Result: ${JSON.stringify(executeResult.result)}`);
          }
          if (executeResult.gas_used) {
            addConsoleMessage('info', `Gas used: ${executeResult.gas_used}`);
          }
        } else {
          addConsoleMessage('error', `Execution failed: ${executeResult.error}`);
        }
      }
    } catch (error: any) {
      addConsoleMessage('error', `Execution error: ${error.message || error}`);
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div className="h-screen flex flex-col bg-gray-900">
      <Toolbar
        onCompile={handleCompile}
        onExecute={handleExecute}
        isCompiling={isCompiling}
        isExecuting={isExecuting}
        fileName={activeFile?.name}
      />
      
      <div className="flex-1 overflow-hidden">
        <PanelGroup direction="horizontal">
          <Panel defaultSize={20} minSize={15} maxSize={25}>
            <FileExplorer />
          </Panel>
          
          <PanelResizeHandle className="w-1 bg-gray-800 hover:bg-blue-600 transition-colors" />
          
          <Panel defaultSize={25} minSize={15} maxSize={30}>
            <MethodExecutor blueprintId={currentBlueprintId} />
          </Panel>
          
          <PanelResizeHandle className="w-1 bg-gray-800 hover:bg-blue-600 transition-colors" />
          
          <Panel ref={codePanelRef} defaultSize={35}>
            <PanelGroup direction="vertical">
              <Panel defaultSize={70}>
                <CodeEditor />
              </Panel>
              
              <PanelResizeHandle className="h-1 bg-gray-800 hover:bg-blue-600 transition-colors" />
              
              <Panel defaultSize={30} minSize={15}>
                <Console />
              </Panel>
            </PanelGroup>
          </Panel>
          
          <PanelResizeHandle className="w-1 bg-gray-800 hover:bg-blue-600 transition-colors" />
          
          <Panel ref={aiPanelRef} defaultSize={20} minSize={3} maxSize={40}>
            <AIAssistant
              isCollapsed={isAICollapsed}
              onToggleCollapse={() => {
                const newCollapsed = !isAICollapsed;
                setIsAICollapsed(newCollapsed);
                
                // Use imperative API to resize panels
                setTimeout(() => {
                  if (aiPanelRef.current && codePanelRef.current) {
                    if (newCollapsed) {
                      // Collapse AI panel to minimum, expand code panel
                      aiPanelRef.current.resize(3);
                      codePanelRef.current.resize(52);
                    } else {
                      // Expand AI panel, shrink code panel
                      aiPanelRef.current.resize(20);
                      codePanelRef.current.resize(35);
                    }
                  }
                }, 10);
              }}
            />
          </Panel>
        </PanelGroup>
      </div>
    </div>
  );
}