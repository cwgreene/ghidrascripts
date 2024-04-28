//Finds functions that are likely constructors and creates data types for them.
//@author diracdelta
//@category CustomerSubmission
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangOpToken;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
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

import functionutils.FunctionCall;
import functionutils.FunctionUtils;
import setup.SetupUtils;

public class FindConstructors extends GhidraScript {
	DecompInterface decomp;
	
    public void run() throws Exception {
        println("Hello world!");
        println(currentProgram == null ? "null" : currentProgram.toString());
        decomp = SetupUtils.setUpDecompiler(currentProgram, state, this);
        FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
        for (Function func : funcs) {
            if (!func.isThunk()) {
                println("-"+func.getName());
                /*for (Function calledFunc : func.getCalledFunctions(monitor)) {
                    String isExternal = calledFunc.isThunk() ? "*" : "";
                    println("--"+ isExternal+ " " + calledFunc.getName());
                    
                }*/
                for (FunctionCall call : FunctionUtils.findCallSites(func, decomp, monitor)) {
                    println("-  " + call.statement.toString());
                }
                for(Variable var : func.getLocalVariables()) {
                	println(" Var: "+ var.getName() + " " + var.getStackOffset());
                }
            }
        }
        
    }
}
