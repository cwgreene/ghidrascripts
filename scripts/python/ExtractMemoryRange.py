#Extracts bytes in memory to file.
#@author diracdelta
#@category Custom
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

endAddress = toAddr(askInt(
	"End Address (from: " + hex(currentAddress.offset) + ")", "End Address:"))

f = open("test.txt", "w")
f.write(bytearray(getBytes(currentAddress,
	endAddress.offset
	-currentAddress.offset)))
f.close()