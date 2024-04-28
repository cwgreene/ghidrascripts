//TODO write a description for this script
//@author diracdelta
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import constants.LinuxX64Syscalls;
import functionutils.FunctionCall;
import functionutils.FunctionUtils;
import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import setup.SetupUtils;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.HighConstant;

public class AnnotateSeccmp extends GhidraScript {
	DecompInterface decomp;
	
    public void run() throws Exception {
        println(currentProgram == null ? "null" : currentProgram.toString());
        decomp = SetupUtils.setUpDecompiler(currentProgram, state, this);
        FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
        for (Function func : funcs) {
            if (!func.isThunk()) {
                for (FunctionCall call : FunctionUtils.findCallSites(func, decomp, monitor)) {
                    if (call.funcName.getText().equals("seccomp_rule_add")) {
                    	// Attempt to convert to int
                    	try {
                    		ClangNode param = call.arguments.get(2);
                            println(param.toString());
                            if (!(param instanceof ClangToken)) {
                                continue;
                            }
                            HighVariable var = ((ClangToken) param).getHighVariable();
                            if (!(var instanceof HighConstant)) {
                                continue;
                            }
                            int callnumber = (int) ((HighConstant)var).getScalar().getValue();
                    		String name = LinuxX64Syscalls.getSyscall(callnumber);
                    		Address loc = param.getMinAddress().subtract(0x12);
                    		Command cmd =
        							new SetEquateCmd(name, loc, 1, callnumber);
        					state.getTool().execute(cmd, currentProgram);
                    	} catch (NumberFormatException e) {
                    		// Do nothing for now, probably log in future.
                    	}
                    }
                }
            }
        }
    }
}
