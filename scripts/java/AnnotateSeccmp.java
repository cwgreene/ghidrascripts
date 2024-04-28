//TODO write a description for this script
//@author diracdelta
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import constants.LinuxX64Syscalls;
import constants.SeccompConstants;
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

    private void labelSysCall(FunctionCall call) {
        ClangNode param = call.arguments.get(2);
        int callnumber = (int) constantParamValue(param);
        String name = LinuxX64Syscalls.getSyscall(callnumber);

        // HACK! MinAddress gives the location of the function call
        // so we just go back to where the compiler typically
        // loads ECX (3rd param)
        Address loc = param.getMinAddress().subtract(0x12);
        Command cmd =
                new SetEquateCmd(name, loc, 1, callnumber);
        state.getTool().execute(cmd, currentProgram);
    }

    private long constantParamValue(ClangNode param){
        println(param.toString());
        HighVariable var = ((ClangToken) param).getHighVariable();
        println(var.toString());
        long value = (int) ((HighConstant)var).getScalar().getValue();
        return value;
    }

    private void labelAction(FunctionCall call) {
        ClangNode actionParam = call.arguments.get(1);
        long action = constantParamValue(actionParam);
        String label = SeccompConstants.actionToString(action);
        // HACK! MinAddress gives the location of the function call
        // so we just go back to where the compiler typically
        // loads RSI (second param)
        Address loc = actionParam.getMinAddress().subtract(0xd);
        Command cmd =
                new SetEquateCmd(label, loc, 1, action);
        state.getTool().execute(cmd, currentProgram);
    }

    private void labelInitAction(FunctionCall call) {
        ClangNode actionParam = call.arguments.get(0);
        print(actionParam.toString());
        long action = constantParamValue(actionParam);
        String label = SeccompConstants.actionToString(action);
        // HACK! MinAddress gives the location of the function call
        // so we just go back to where the compiler typically
        // loads RSI (second param)
        Address loc = actionParam.getMinAddress().subtract(0x5);
        Command cmd =
                new SetEquateCmd(label, loc, 1, action);
        state.getTool().execute(cmd, currentProgram);
    }

    public void annotate_seccomp_rule_add(FunctionCall call) {
        try {
            labelSysCall(call);
            labelAction(call);
        } catch (java.lang.ClassCastException e) {
            println("Could not annotate: " + call.toString());
        }
    }

    public void annotate_seccomp_init(FunctionCall call) {
        try {
            labelInitAction(call);
        } catch (java.lang.ClassCastException e) {
            println("Could not annotate: " + call.toString());
        }
    }

	
    public void run() throws Exception {
        FunctionUtils.setPrinter(this);
        println(currentProgram == null ? "null" : currentProgram.toString());
        decomp = SetupUtils.setUpDecompiler(currentProgram, state, this);
        FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
        for (Function func : funcs) {
            if (!func.isThunk()) {
                for (FunctionCall call : FunctionUtils.findCallSites(func, decomp, monitor)) {
                    if (call.funcName.getText().equals("seccomp_rule_add")) {
                        annotate_seccomp_rule_add(call);
                    } else if (call.funcName.getText().equals("seccomp_init")) {
                        annotate_seccomp_init(call);
                    }
                }
            }
        }
    }
}
