//Select namespace for currently selected function
//@author 
//@category _TQ
//@keybinding 
//@menupath Tools.ChooesThisSymbol
//@toolbar 

import java.util.ArrayList;
import java.util.Comparator;
import java.util.SortedSet;
import java.util.TreeSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class ChooseThisSymbol extends GhidraScript {
	
	private static GhidraClass selected = null;

	public void run() throws Exception {

		FunctionManager functionManager = currentProgram.getFunctionManager();
		Function function = functionManager.getFunctionAt(currentAddress);
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		SymbolIterator symbolIterator = symbolTable.getSymbolIterator(true);

		SortedSet<GhidraClass> classList = new TreeSet<GhidraClass>(new Comparator<GhidraClass>() {
			@Override
			public int compare(GhidraClass s1, GhidraClass s2) {
				return s1.getName(true).compareTo(s2.getName(true));
			}
		});

		while (symbolIterator.hasNext()) {
			Symbol symbol = symbolIterator.next();
			if (symbol.getName().contentEquals("`vftable'")) {
				classList.add((GhidraClass) symbol.getParentNamespace());
			}
		}

		if (function == null) {
			println("Select function first!");
			return;
		}

		selected = askChoice("Choose class", "Class:", new ArrayList<GhidraClass>(classList), selected);

		function.setParentNamespace(selected);
	}
}
