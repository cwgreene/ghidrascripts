//@keybinding Shift-X

import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;

public class SmallEquate extends GhidraScript {

	@Override
	public void run() throws Exception {
		// Get listing for current program
		Listing listing = currentProgram.getListing();

		// bools to be able to inform user if scalar values were found
		boolean scalarFound = false;
		boolean userScalarFound = false;

		// Iterator declarations
		InstructionIterator iter;

		// Check to see if there is a selection
		if (currentSelection != null) {
			// Create iterator to check current selection
			iter = listing.getInstructions(currentSelection, true);
		}
		else {
			// Create iterator to check whole program
			return;
		}

		// checks if there is a next value and if the user has canceled the
		// request
		while (iter.hasNext() && !monitor.isCancelled()) {
			// Grabs next value
			Instruction tempValue = iter.next();

			// Find out how many operands are listed
			int numOperands = tempValue.getNumOperands();

			for (int i = 0; i <= numOperands; i++) {
				// Checks to see if the current value is a scalar value
				if (tempValue.getOperandType(i) == (OperandType.SCALAR)) {

					scalarFound = true; // a scalar value was found

					// Checks to see if the scalar value is equal to the value
					// we are searching for
					if (tempValue.getScalar(i).getUnsignedValue() < 256) {

						userScalarFound = true; // the scalar value the user was
												// looking for was found

						// Sets the equate to the user defined name and execute
						String equateName = "0x"+tempValue.getAddress().toString();
						Command cmd =
							new SetEquateCmd(equateName, tempValue.getAddress(), i, tempValue.getScalar(i).getUnsignedValue());
						state.getTool().execute(cmd, currentProgram);

						// print out the new information for user
						println("A new equate named " + equateName +
							" has been set for the scalar value at address " +
							tempValue.getAddress() + " and at operand " + i);
					}
				}
			}
		}
		// checks to see if the scalar value was found and informs user
		if (scalarFound == false) {
			println("No scalar values were found.");
		}
		else if (scalarFound == true) {
			println("No values were found");
		}
	}
}
