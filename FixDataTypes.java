
//Fix table data type
//@author 
//@category _TQ
//@keybinding 
//@menupath Tools.FixDataTypes
//@toolbar 
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.data.Structure;

public class FixDataTypes extends GhidraScript {

	@Override
	protected void run() throws Exception {

		if (currentProgram == null) {
			return;
		}

		if (!currentProgram.hasExclusiveAccess()) {
			popup("This script requires an exclusive checkout of the program");
			return;
		}

		var p = currentProgram.getListing().getDataTypeManager();
		
		DataTypeManagerDB dtm = (DataTypeManagerDB) currentProgram.getDataTypeManager();
		var archives = dtm.getSourceArchives();
		
		printf("%s %s", p, dtm);

		SourceArchive tqArchive = null;
		for (SourceArchive archive : archives) {
			printf("Archive %s\n", archive.getName());
			if (archive.getName().compareTo("TQ") == 0) {
				tqArchive = archive;
			}
		}

		{
			var archive = dtm.getLocalSourceArchive();
			printf("Archive %s\n", archive.getName());
			List<DataType> dataTypes = dtm.getDataTypes(archive);
			printf("Archive count %d\n", dataTypes.size());

			for (DataType dt : dataTypes) {
				//FunctionDefinition
				if(dt instanceof Structure) {
					//dtm.associateDataTypeWithArchive(dt, tqArchive);
				}
			}
		}
		
		var list = new LinkedList<DataType>();
		dtm.findDataTypes("Character", list);
		for(DataType dt : list) {
			printf("%s %s\n", dt.getPathName(), dt.getSourceArchive().getName());
		}
	} // end 'run'
}
