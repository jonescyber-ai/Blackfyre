package blackfyre.datatypes.ghidra;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;

import blackfyre.datatypes.BinaryContext;
import blackfyre.datatypes.DataType;
import blackfyre.datatypes.DefinedData;
import blackfyre.datatypes.DisassemblerType;
import blackfyre.datatypes.Endness;
import blackfyre.datatypes.ExportSymbol;
import blackfyre.datatypes.FileType;
import blackfyre.datatypes.FunctionContext;
import blackfyre.datatypes.ImportSymbol;
import blackfyre.datatypes.ProcessorType;
import blackfyre.datatypes.WordSize;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.DefinedDataIterator;
import ghidra.util.task.TaskMonitor;

public class GhidraBinaryContext extends BinaryContext{

    private boolean theIsInitialized = false;

    protected Program theCurrentProgram;

    protected TaskMonitor theMonitor;

    protected boolean theIncludeDecompiledCode;

    protected int theDecompileTimeoutSeconds;

    public GhidraBinaryContext(Program currentProgram,TaskMonitor monitor, boolean includeDecompiledCode, int decompileTimeoutSeconds )

    {
        super();

        theCurrentProgram = currentProgram;
        theMonitor = monitor;
        theIncludeDecompiledCode = includeDecompiledCode;
        theDecompileTimeoutSeconds = decompileTimeoutSeconds;

    }

    public boolean initialize() throws Exception
    {

        if(theIsInitialized)
        {
            return theIsInitialized;
        }

        // Binary Name
 		theName = getBinaryNameFromGhidra();

//     	    // Binary Sha256
     	theSHA256Hash = getBinarySHA256FromGhidra();

//     		//Word size
     	theWordSize = getWordSizeFromGhidra();


 		// File Type
 		theFileType  = getFileTypeFromGhidra();


 		// Processor Type
 		theProcType = getProcessTypeFromGhidra();

 		// Endness
 		theEndness = getEndnessFromGhidra();



 		theLanguageID = getLanguageIDFromGhidra();

        theStringRefs = getStringRefsFromGhidra();

        theImportSymbols = getImportSymbolsFromGhidra();

        theFunctionContexts = getDisassemblyFunctionListFromGhidra();

        theTotalFunctions =theFunctionContexts.length;

        theTotalInstructions = getTotalInstructionsFromGhidra();


        theDisassemblerType = DisassemblerType.Ghidra;

        theCalleeToCallersMap = getCalleeToCallersMapFromGhidra();

        theCallerToCalleesMap = getCallerToCalleesMap();

        theRawBinaryFilePath = getRawBinaryFilePathFromGhidra();

        theDefinedDataMap = getDefinedDataRefsFromGhidra();

        theExportSymbols = getExportSymbolsFromGhidra();

        theFileSize = getFileSizeFromGhidra();

        theDisassemblerVersion = getDisassemblerVersionFromGhida();


        initializeHeader();



        theIsInitialized = true;

        return theIsInitialized;
    }

    protected void initializeHeader() throws Exception
    {
    	//Intentionally left blank.  For children that need to initialize their header
    }

    protected HashMap<Long,ArrayList<Long> >  getCalleeToCallersMapFromGhidra()
    {

    	HashMap<Long,ArrayList<Long>> calleeToCallersMap = new HashMap<Long,ArrayList<Long>>();

    	ReferenceManager referenceManager = theCurrentProgram.getReferenceManager();

    	FunctionManager functionManager = theCurrentProgram.getFunctionManager();


    	// Iterate of each function to get its callers
    	for( Function ghidraFunction : theCurrentProgram.getFunctionManager().getFunctions(true))
		{

    		Long calleeAddress = ghidraFunction.getEntryPoint().getOffset();

    		ArrayList<Long> callerList = new ArrayList<Long>() ;

			//println(String.format("(0x%08X) %s", functionAddress, ghidraFunction.getName()));


    		// Get the callers of the current function
    		for ( var reference: referenceManager.getReferencesTo(ghidraFunction.getEntryPoint()))
    		{

    			// Caller's address
    			Address callerAddress = reference.getFromAddress();


    			// Check that the caller address is a function
    			Function callerFunction = functionManager.getFunctionContaining(callerAddress);
    			if(callerFunction == null)
    			{
    				// Address does not belong to address, go to the next reference
    				//println(String.format("\tCaller (0x%08X) is not a function", callerAddress.getOffset()));
    				continue;
    			}
    			//println(String.format("\tCaller (0x%08X) %s", callerFunction.getEntryPoint().getOffset(), callerFunction.getName()));


    			// Add the caller's address to the list
    			callerList.add(callerFunction.getEntryPoint().getOffset());

    		}

    		// Add the caller information of the target function to the map
    		calleeToCallersMap.put(calleeAddress, callerList);

		}

    	return calleeToCallersMap;
    }


    protected int getTotalInstructionsFromGhidra()
    {
    	int totalInstructions = 0;

    	for( @SuppressWarnings("unused") Instruction instruction : theCurrentProgram.getListing().getInstructions(true))
    	{
    		totalInstructions +=1;
    	}


    	return totalInstructions;
    }


    protected HashMap<Long, ArrayList<Long>>  getCallerToCalleesMap() throws Exception
	{

    	// Check that the callermap has already been initialized
    	if(theCalleeToCallersMap == null)
    	{
    		throw new Exception("Attribute 'theCAllerMap' is not initialized");
    	}

		// From the caller map, we can derive the callee map
		HashMap<Long, ArrayList<Long>> callerToCallees = new HashMap<Long, ArrayList<Long>>();

		for( var callee2CallersEntry: theCalleeToCallersMap.entrySet() )
		{
			Long calleeAddress = callee2CallersEntry.getKey();

			for ( var callerAddress : callee2CallersEntry.getValue())
			{

				ArrayList<Long> calleeList  = callerToCallees.get(callerAddress);
				// Check if the ArrayList has been initialized
				if(calleeList == null)
				{
					calleeList  = new ArrayList<Long>();

					// Add the key:list pair to the map
					callerToCallees.put(callerAddress, calleeList);
				}

				// Add the callee address to the list
				calleeList.add(calleeAddress);

				//println(String.format("\tCaller (0x%08X) --> Callee (0x%08X) ", callerAddress, calleeAddress));
			}

		}

		return callerToCallees;
	}


    protected FunctionContext [] getDisassemblyFunctionListFromGhidra()
	{

		ArrayList<FunctionContext>  functionContextArrayList  =  new ArrayList<FunctionContext>();



		for( Function ghidraFunction : theCurrentProgram.getFunctionManager().getFunctions(true))
		{
			GhidraFunctionContext ghidraFunctionContext = new GhidraFunctionContext(theCurrentProgram,
																					ghidraFunction,
																					theMonitor,
																					getProcType(),
																					theIncludeDecompiledCode,
																					theDecompileTimeoutSeconds);

			functionContextArrayList.add(ghidraFunctionContext);


		}

		FunctionContext [] functionContexts = functionContextArrayList.toArray(new FunctionContext[functionContextArrayList.size()]);


		return functionContexts;
	}

    protected HashMap<Long, DefinedData> getDefinedDataRefsFromGhidra() throws Exception
    {
    	HashMap<Long, DefinedData> definedDataRefs = new HashMap<Long, DefinedData>();

    	for (var data: theCurrentProgram.getListing().getDefinedData(true))
    	{
    		//System.out.println("DataType is: "+data.getDataType());

    		DefinedData definedData = null;
    		DataType dataType = null;

			if(data.getDataType() instanceof WordDataType )
			{
				dataType = DataType.WORD;

			}
			else if(data.getDataType() instanceof DWordDataType)
			{

				dataType = DataType.DWORD;

			}
			else if(data.getDataType() instanceof QWordDataType)
			{

				dataType = DataType.QWORD;

			}
			else if(data.getDataType() instanceof Pointer )
			{

				if(data.getLength() == 4)
				{
					dataType = DataType.POINTER32;
				}
				else if (data.getLength() ==  8)
				{
					dataType = DataType.POINTER64;
				}

			}


			if(dataType != null)
			{

				ArrayList<Long>  references  =  new ArrayList<Long>();

				long definedDataAddress = data.getAddress().getOffset();


				for(var reference :  theCurrentProgram.getReferenceManager().getReferencesTo(data.getAddress()))
				{
					long referenceFromAddress = reference.getFromAddress().getOffset();

					references.add(referenceFromAddress);

				}

				try
				{

					definedData = new DefinedData(definedDataAddress,data.getBytes(),dataType, references ,data.getLength());

					definedDataRefs.put(definedDataAddress, definedData);
				}
				catch(Exception e)
				{
					// Do nothing... we are unable to get the defined data
				}

			}

    	}



    	return definedDataRefs;
    }


    protected HashMap<Long,String> getStringRefsFromGhidra()
    {
    	
        HashMap<Long,String> stringRefs = new HashMap<Long,String>();
        
        Listing listing = theCurrentProgram.getListing();

        // Iterate through the program to get string refs
        var definedDataInterator  =  listing.getDefinedData(true);
        for( var definedData: definedDataInterator)
        {
            if(definedData.hasStringValue())
            {
                String programString = definedData.getDefaultValueRepresentation();

//              String progressMessage = String.format("[0x%08X] String: %s",
//                        definedData.getAddress().getOffset(),
//                        programString);
//              System.out.println(progressMessage);

                var refenceInterator = theCurrentProgram.getReferenceManager().getReferencesTo(definedData.getAddress());

                for ( var reference : refenceInterator)
                {

                    long referenceFromAddress = reference.getFromAddress().getOffset();


                    stringRefs.put(referenceFromAddress, programString);

                }

            }
        }

        return stringRefs;
    }


    protected ImportSymbol [] getImportSymbolsFromGhidra()
    {

        ArrayList<ImportSymbol>  importSymbolList  =  new ArrayList<ImportSymbol>();

        for(Function function : theCurrentProgram.getFunctionManager().getFunctions(true))
        {
            // Only add thunks to symbol list
            if(function.isThunk())
            {
                Function thunkedFunction = function.getThunkedFunction(true);

                if(thunkedFunction != null && thunkedFunction.getExternalLocation() != null)
                {
                    String functionName = function.getName();
                    String libraryName = thunkedFunction.getExternalLocation().getLibraryName();
                    long address = function.getEntryPoint().getOffset();

                    ImportSymbol importSymbol = new ImportSymbol(functionName, libraryName, address);

                    importSymbolList.add(importSymbol);
                }
            }
        }


        // Iterate over symbols
        for(Symbol symbol : theCurrentProgram.getSymbolTable().getExternalSymbols())
        {
        	String importName = symbol.getName();
        	String libraryName = "";
        	long address = 0;



        	// An indirect method to get the address where the symbol is defined that works.  The direct approaches such as
        	// getting the symbol.getAddress() or symbol.getProgramLocation().getAddress() or external function did not return
        	// valid addresses.
        	if(symbol.hasReferences())
        	{
        		address = symbol.getReferences()[0].getFromAddress().getOffset();

        	}


        	Symbol parentSymbol = symbol.getParentSymbol();
        	if (parentSymbol != null)
        	{
        		libraryName = parentSymbol.getName();
        	}

        	ImportSymbol importSymbol = new ImportSymbol(importName, libraryName, address);
            importSymbolList.add(importSymbol);

        }


        ImportSymbol [] importSymbols = importSymbolList.toArray(new ImportSymbol[importSymbolList.size()]);


        return importSymbols;
    }

    protected ExportSymbol[] getExportSymbolsFromGhidra() {
        ArrayList<ExportSymbol> exportSymbolList = new ArrayList<ExportSymbol>();

        // Get the symbol table for the current program
        var symbolTable = theCurrentProgram.getSymbolTable();

        // Iterate over all global symbols in the symbol table
        for (Symbol symbol : symbolTable.getAllSymbols(false)) {
            // Check if the symbol is an exported function
            if (symbol.isExternalEntryPoint()) {
                // Get the name, library name, and address of the exported function
                String functionName = symbol.getName();
                String libraryName = symbol.getParentNamespace().getName();
                long address = symbol.getAddress().getOffset();

                // Create a new ExportSymbol object and add it to the list
                ExportSymbol exportSymbol = new ExportSymbol(functionName, libraryName, address);
                exportSymbolList.add(exportSymbol);
            }
        }

        // Convert the list of ExportSymbols to an array and return it
        ExportSymbol[] exportSymbols = exportSymbolList.toArray(new ExportSymbol[exportSymbolList.size()]);
        return exportSymbols;
    }


    public String getLanguageIDFromGhidra()
	{

		return theCurrentProgram.getLanguageID().getIdAsString();
	}

    public DisassemblerType getDisassemblyType()
    {
    	return theDisassemblerType;
    }

    public String getBinaryNameFromGhidra()
	{
		return theCurrentProgram.getName();
	}

	public String getBinarySHA256FromGhidra()
	{
		return theCurrentProgram.getExecutableSHA256();
	}

	public WordSize getWordSizeFromGhidra()
	{
		return getWordSize(theCurrentProgram);
	}

	public static WordSize  getWordSize(Program program)
	{
		int wordSize = program.getDefaultPointerSize();

		WordSize archWordSize;

		switch(wordSize) {

		case 8 : archWordSize =WordSize.BITS_64;
		         break;

		case 4 : archWordSize= WordSize.BITS_32;
				 break;

		case 2 : archWordSize= WordSize.BITS_16;
		         break;

		default: throw new RuntimeException("Unsupported word size: "+wordSize);

		}

		return archWordSize;

	}

	public FileType getFileTypeFromGhidra()
	{
		return GhidraBinaryContext.getFileTypeFromGhidra(theCurrentProgram);
	}

	public static FileType getFileTypeFromGhidra(Program program)
	{
		String executableFormat = program.getExecutableFormat();

		WordSize wordSize = GhidraBinaryContext.getWordSize(program);

		FileType fileType;

		if(executableFormat.contains("ELF") && wordSize== WordSize.BITS_64)
		{
			fileType = FileType.ELF64;

		}
		else if (executableFormat.contains("ELF"))
		{
			fileType = FileType.ELF32;
		}
		else if(executableFormat.contains("PE") && wordSize== WordSize.BITS_64)
		{
			fileType = FileType.PE64;

		}
		else if (executableFormat.contains("PE"))
		{
			fileType = FileType.PE32;
		}

		else if (executableFormat.contains("Mach-O")  && wordSize== WordSize.BITS_32)
		{
			fileType = FileType.MACH_O_32;
		}
		else if (executableFormat.contains("Mach-O")  && wordSize== WordSize.BITS_64)
		{
			fileType = FileType.MACH_O_64;
		}

		else
		{
			throw new RuntimeException("Unsupported executable format: "+executableFormat);
		}


		return fileType;

	}

	public ProcessorType getProcessTypeFromGhidra()
	{

		WordSize wordSize = getWordSizeFromGhidra();

		String processName = theCurrentProgram.getLanguage().getProcessor().toString();

		ProcessorType processorType;

		if(processName.contains("x86") && wordSize == WordSize.BITS_32)
		{
			processorType = ProcessorType.x86;
		}
		else if(processName.contains("x86") && wordSize == WordSize.BITS_64)
		{
			processorType = ProcessorType.x86_64;
		}
		else if (processName.contains("ARM") )
		{
			processorType = ProcessorType.ARM;
		}
		else if (processName.contains("MIPS"))
		{
			processorType = ProcessorType.MIPS;
		}
		else if (processName.contains("PowerPC"))
		{
			processorType = ProcessorType.PPC;
		}
		else if (processName.contains("AARCH64"))
		{
			processorType = ProcessorType.AARCH64;
		}
		else
		{
			throw new RuntimeException("Unsupporteds processor type: "+processName);
		}


		return processorType;

	}

	public Endness getEndnessFromGhidra()
	{

		Endness endness = Endness.LITTLE_ENDIAN;

		if(theCurrentProgram.getLanguage().isBigEndian())
		{
			endness = Endness.BIG_ENDIAN;
		}


		return endness;
	}

	public Path getRawBinaryFilePathFromGhidra() {
	    String executablePath = theCurrentProgram.getExecutablePath();

	    // Convert to a File to handle platform-specific path nuances
	    File file = new File(executablePath);

	    // Convert File to a Path, ensuring it's platform-independent
	    Path path = file.toPath().toAbsolutePath().normalize();

	    return path;
	}
	
	public long getFileSizeFromGhidra() throws IOException 
	{
		Path path = getRawBinaryFilePathFromGhidra();
		
		long fileSize = Files.size(path);
		
		
		return fileSize;
	}
	
	public String getDisassemblerVersionFromGhida()
	{
		String ghidraVersion = Application.getApplicationVersion();
		
		return ghidraVersion;
	}
	
	


}
