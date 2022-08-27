//Create virtual table data type
//@author 
//@category _TQ
//@keybinding 
//@menupath Tools.CreateVtbl
//@toolbar 

import java.util.ArrayList;
import java.util.HashSet;

import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.StringColumnDisplay;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

public class CreateVirtualTable extends GhidraScript {
	
	static DataType selectedType = null;

	public void run() throws Exception {
		long vtblSize = currentSelection.getNumAddresses();
		if (vtblSize % 4 > 0 || vtblSize == 0) {
			println("invalid table selection");
			return;
		}

		Address addressMin = currentSelection.getMinAddress();
		Address addressMax = currentSelection.getMaxAddress();

		Data data = getDataAt(addressMin);

		println(data.getMnemonicString());

		TableChooserDialog tableDialog = createTableChooserDialog("Configure virtual table", null);
		configureTableColumns(tableDialog);

		Address current = addressMin;
		var virtualFunctions = new ArrayList<Function>();
		while (current.getOffset() <= addressMax.getOffset()) {
			var entry = new VirtualFunctionEntry(current);
			tableDialog.add(entry);
			virtualFunctions.add(entry.getFunction());
			current = current.add(4);
		}

		selectedType = selectDataType(selectedType);
		CategoryPath selectedPath = selectedType.getCategoryPath();

		DataTypeManager dtm = currentProgram.getDataTypeManager();
		
		CategoryPath vtblPath = new CategoryPath(selectedPath, selectedType.getName() + "_Vtbl");
		Category vtblCategory = dtm.getCategory(vtblPath);
		if(vtblCategory == null) {
			vtblCategory = dtm.createCategory(vtblPath);
		}

		var names = new HashSet<String>();
		names.add("_Vtbl");
		var virtualFunctionsDT = new ArrayList<DataType>();
		var vtblType = new StructureDataType(vtblPath, "_Vtbl", 0);

		for(Function f : virtualFunctions)
		{
			String name = getUniqueName(f.getName(), names);
			names.add(name);
			
			println(name);
			
			var fdt = dtm.getDataType(vtblPath, name);
			if(fdt == null) {
				fdt = new FunctionDefinitionDataType(vtblPath, name, f.getSignature(), dtm);
			}
			else {
				fdt = dtm.replaceDataType(fdt, new FunctionDefinitionDataType(vtblPath, name, f.getSignature()), false);
			}
			
			virtualFunctionsDT.add(fdt);
			
			vtblType.add(new PointerDataType(fdt), name, "");
		}
		
		var oldVtbl = dtm.getDataType(vtblPath, "_Vtbl");
		if(oldVtbl == null) {
			dtm.addDataType(vtblType, DataTypeConflictHandler.REPLACE_HANDLER);
		}
		else {
			dtm.replaceDataType(oldVtbl, vtblType, false);
		}
		
		for(DataType dt : vtblCategory.getDataTypes() ) {
			println(dt.getName());
		}
		
		createData(addressMin, vtblType);

		((Structure)selectedType).replaceAtOffset(0, new PointerDataType(vtblType), 4, "vtbl", "");
		
		tableDialog.show();
	}
	
	private String getUniqueName(String name, HashSet<String> names)
	{
		int i = 0;
		var uniqueName = name;
		while(names.contains(uniqueName))
		{
			uniqueName = name +i;
			++i;
		}
		
		return uniqueName;
	}

	private DataType selectDataType(DataType initialType) {
		PluginTool tool = state.getTool();
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		DataTypeSelectionDialog selectionDialog = new DataTypeSelectionDialog(tool, dtm, -1,
				AllowedDataTypes.FIXED_LENGTH);
		
		if(initialType != null) {
			selectionDialog.setInitialDataType(initialType);
		}
		
		tool.showDialog(selectionDialog);

		DataType dataType = selectionDialog.getUserChosenDataType();
		println("Chosen data type: " + dataType);
		return dataType;
	}

////////////////////////////////////////////////////////////////////////////////////
//                          table stuff                                           //
////////////////////////////////////////////////////////////////////////////////////

	private void configureTableColumns(TableChooserDialog dialog) {
		StringColumnDisplay explanationColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Name";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				VirtualFunctionEntry entry = (VirtualFunctionEntry) rowObject;
				return entry.getName();
			}
		};

		dialog.addCustomColumn(explanationColumn);
	}

	class VirtualFunctionEntry implements AddressableRowObject {
		Address address;
		Reference reference;
		Data data;
		Function function;

		public VirtualFunctionEntry(Address a) throws Exception {
			address = a;
			data = getDataAt(a);
			if(data == null) {
				data = createData(a, Pointer32DataType.dataType);
			}
			reference = data.getPrimaryReference(0);
			Address referenceAddress = reference.getToAddress();
			function = getFunctionAt(referenceAddress);
			
			removeDataAt(a);
		}

		public Function getFunction() {
			return function;
		}
		
		public String getName() {
			return function.getName();
		}

		@Override
		public Address getAddress() {
			return address;
		}
	}
}
