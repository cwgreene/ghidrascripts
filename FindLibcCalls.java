//TODO write a description for this script
//@author 
//@category CustomerSubmission
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
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

public class FindLibcCalls extends GhidraScript {

    public void run() throws Exception {
    	println("Hello world!");
    	FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
    	for (Function func : funcs) {
    		if (!func.isThunk()) {
	    		println("-"+func.getName());
	    		for (Function calledFunc : func.getCalledFunctions(monitor)) {
	    			String isExternal = calledFunc.isThunk() ? "*" : "";
	    			println("--"+ isExternal+ " " + calledFunc.getName());
	    		}
    		}
    	}
    }

}
