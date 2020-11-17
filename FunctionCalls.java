//TODO write a description for this script
//@author 
//@category CustomerSubmission
//@keybinding 
//@menupath 
//@toolbar 

import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;


import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangOpToken;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.Tool;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.util.*;
import ghidra.sleigh.grammar.SleighCompiler.identifier_return;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class FunctionCalls extends GhidraScript {
    
    private DecompInterface decomp;
    
    class FunctionCall {
        ClangFuncNameToken funcName;
        List<ClangNode> arguments;
        ClangStatement statement;
        public FunctionCall(ClangFuncNameToken funcName, List<ClangNode> arguments, ClangStatement statement) {
            this.funcName = funcName;
            this.arguments = arguments;
            this.statement = statement;
        }
    }
    
    private FunctionCall analyzeCall(ClangStatement clangStatement) {
    	ObjectMapper bbjectMapper = new ObjectMapper();
        ClangFuncNameToken funcName = null;
        List<ClangNode> arguments = new ArrayList<>();
        for (int i = 0; i < clangStatement.numChildren(); i++ ) {
            ClangNode child = clangStatement.Child(i);
            if (child instanceof ClangOpToken) {
                ClangOpToken optoken = (ClangOpToken) child;
                // I can't imagine this is the best way but...
                if (optoken.toString().contentEquals(",")) {
                    continue;
                }
                println("optoken:"+optoken.getText());
                arguments.add(optoken);
            } else if (child instanceof ClangVariableToken) {
            	ClangVariableToken varToken = (ClangVariableToken) child;
            	HighVariable var = varToken.getHighVariable();
            	println("var "+varToken.getText()+ " "+var);
                arguments.add(child);
            } else if (child instanceof ClangFuncNameToken) {
                funcName = (ClangFuncNameToken) child;
            }
        }
        return new FunctionCall(funcName, arguments, clangStatement);
    }
    
    private List<FunctionCall> findCallSites(Function func) {
        List<FunctionCall> result = new ArrayList<>();
        DecompileResults res = decomp.decompileFunction(func, 60, monitor);
        List<ClangNode> tokens = new ArrayList<>();
        res.getCCodeMarkup().flatten(tokens);
        for(ClangNode token : tokens) {
            if (token instanceof ClangFuncNameToken) {
                if (token.Parent() instanceof ClangStatement) {
                    ClangStatement statement = (ClangStatement) token.Parent();
                    if (statement.getPcodeOp().getMnemonic().equals("CALL")) {
                        result.add(analyzeCall(statement));
                    }
                }
            }
        }
        return result;
    }
    
    private Variable findVariableByName(Variable[] variables, String name) {
    	for(Variable v : variables) {
    		if(v.getName().equals(name)) {
    			return v;
    		}
    	}
    	return null;
    }

    public void run() throws Exception {
    	String[] arguments = getScriptArgs();
    	println("hey");
        decomp = setUpDecompiler(currentProgram);
        FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
        for (Function callingFunc : funcs) {
            if (!callingFunc.isThunk()) {
                for (FunctionCall call : findCallSites(callingFunc)) {
                	if(call.funcName.getText().equals("gets")) {
                		ClangNode node = call.arguments.get(0);
                		if (node instanceof ClangVariableToken) {
                			ClangVariableToken buffer = (ClangVariableToken) node;
                			Variable buf = findVariableByName(callingFunc.getAllVariables(), buffer.getText());
                			println(buf.getStackOffset() + " " + buffer.getText());
                		}
                	}
                }
            }
        }
    }
    
    
    public void dumpFunctions() {
        println(currentProgram == null ? "null" : currentProgram.toString());
        decomp = setUpDecompiler(currentProgram);
        FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
        for (Function callingFunc : funcs) {
            if (!callingFunc.isThunk()) {
                println("-"+callingFunc.getName());
                for (FunctionCall call : findCallSites(callingFunc)) {
                	println("-  " + call.statement.toString());
                }
                for(Variable var : callingFunc.getLocalVariables()) {
                	println(" Var: "+ var.getName() + " " + var.getStackOffset());
                }
            }
        }
    }
    
    private DecompInterface setUpDecompiler(Program program) {
        DecompInterface decompInterface = new DecompInterface();

        // call it to get results
        if (!decompInterface.openProgram(currentProgram)) {
            println("Decompile Error: " + decompInterface.getLastMessage());
            return null;
        }

        DecompileOptions options;
        options = new DecompileOptions();
        
        println(state.getTool() == null ? "No tool!" : state.getTool().getName());
        PluginTool currentTool = state.getTool();
        if (currentTool != null) {
            OptionsService service = state.getTool().getService(OptionsService.class);
            if (service != null) {
                ToolOptions opt = service.getOptions("Decompiler");
                options.grabFromToolAndProgram(null, opt, program);
            }
        }
        decompInterface.setOptions(options);

        decompInterface.toggleCCode(true);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.setSimplificationStyle("decompile");

        return decompInterface;
    }
}
