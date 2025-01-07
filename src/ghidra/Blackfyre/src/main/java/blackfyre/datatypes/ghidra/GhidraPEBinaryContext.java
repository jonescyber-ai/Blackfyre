package blackfyre.datatypes.ghidra;

import java.io.File;

import blackfyre.datatypes.PEHeader;
import blackfyre.protobuf.BinaryContextOuterClass;
import blackfyre.protobuf.PEHeaderOuterClass;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.bin.format.pe.FileHeader;
import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class GhidraPEBinaryContext extends GhidraBinaryContext {
    
    private boolean theIsInitialized = false;

    protected Program theCurrentProgram;

    protected TaskMonitor theMonitor;
    
    protected PEHeader thePEHeader;

    
    public GhidraPEBinaryContext(Program currentProgram, 
    		                     TaskMonitor monitor, 
    		                     boolean includeDecompiledCode, int decompileTimeoutSeconds)
    {
        super(currentProgram, monitor, includeDecompiledCode, decompileTimeoutSeconds);
        
        theCurrentProgram = currentProgram;
        theMonitor = monitor;
    }
    
    public PEHeader getPEHeader()
    {
    	return thePEHeader;
    }
    
        
    protected void  initializeHeader() throws Exception
    {
    	File exePath = new File(theCurrentProgram.getExecutablePath());
        String path = exePath.getAbsolutePath();

        // Windows default, if starts with a / then it is a linux system
        String prefix = "file://";
        if (path.startsWith("/")) {
            prefix = "file:/";
        }
        FSRL fsrl = FSRL.fromString(prefix + path);

        FileByteProvider provider = new FileByteProvider(exePath, fsrl, java.nio.file.AccessMode.READ);
        
    
        // Create the PortableExecutable object
        PortableExecutable portableExecutable = null;
        portableExecutable = new PortableExecutable( provider,PortableExecutable.SectionLayout.FILE);

        FileHeader fileHeader = portableExecutable.getNTHeader().getFileHeader();
        OptionalHeader optionalHeader = portableExecutable.getNTHeader().getOptionalHeader();

        
        // **Initialize the PE header attributes**
        
        int timeStamp = fileHeader.getTimeDateStamp();
        long sizeOfImage = optionalHeader.getSizeOfImage();
        long addressOfEntryPoint =  optionalHeader.getAddressOfEntryPoint();        
        long sizeOfInitializedData = optionalHeader.getSizeOfInitializedData();
        
        long sizeOfCode = optionalHeader.getSizeOfCode();
        int  sizeOfRawData = getSizeOfRawData(fileHeader);
        int checksum = optionalHeader.getChecksum();
        int dllCharacteristics = optionalHeader.getDllCharacteristics();
        
        int numberOfSections = fileHeader.getNumberOfSections();        
        int majorLinkerVersion = optionalHeader.getMajorLinkerVersion();
        int majorImageVersion = optionalHeader.getMajorImageVersion();
        long sizeOfUnitializedData = optionalHeader.getSizeOfUninitializedData();
        
        long baseOfCode = optionalHeader.getBaseOfCode();       
        int minorLinkerVersion = optionalHeader.getMinorLinkerVersion();        
        int sizeOfHeaders = getSizeOfHeaders(fileHeader);
        int majorOperatingSystemVersion = optionalHeader.getMajorOperatingSystemVersion();
        
        long sizeOfStackReserve = optionalHeader.getSizeOfStackReserve();
        int fileAlignment = optionalHeader.getFileAlignment();
        int minorImageVersion = optionalHeader.getMinorImageVersion();
        int majorSubsystemVersion = optionalHeader.getMajorSubsystemVersion();
        
        long sizeofStackCommit = optionalHeader.getSizeOfStackCommit();
        long sizeOfHeapReserve = optionalHeader.getSizeOfHeapReserve();       
        String ntHeaderName = portableExecutable.getNTHeader().getName();
        
                
        
        thePEHeader = new PEHeader(timeStamp,sizeOfImage, addressOfEntryPoint, sizeOfInitializedData,
        		sizeOfCode, sizeOfRawData, checksum, dllCharacteristics, numberOfSections,
        		majorLinkerVersion , majorImageVersion, sizeOfUnitializedData, baseOfCode,
        		minorLinkerVersion, sizeOfHeaders, majorOperatingSystemVersion, sizeOfStackReserve,
        		fileAlignment , minorImageVersion, majorSubsystemVersion , sizeofStackCommit ,
        		sizeOfHeapReserve ,ntHeaderName ) ;
    	

        provider.close();
    }
    
    public BinaryContextOuterClass.BinaryContext toPB() throws Exception
    {
    	
    	var binaryContextBuilder = initializeBinaryContextBuilder();
    	
    	PEHeaderOuterClass.PEHeader peHeaderPB = thePEHeader.toPB();
    	
    	binaryContextBuilder.setPeHeader(peHeaderPB);
    	
    	
    	return binaryContextBuilder.build();
    	
    }
    
    private static int getSizeOfHeaders(FileHeader fileHeader)
    {
    	int totalSizeOfHeaders = 0;
    	
    	for(var sectionHeader: fileHeader.getSectionHeaders())
    	{
    		totalSizeOfHeaders += sectionHeader.getVirtualSize();
    	}
    	
    	return totalSizeOfHeaders;
    }
    
    private static int getSizeOfRawData(FileHeader fileHeader)
    {
    	int totalSizeOfRawData = 0;
    	
    	for(var sectionHeader: fileHeader.getSectionHeaders())
    	{
    		totalSizeOfRawData += sectionHeader.getSizeOfRawData();
    	}
    	
    	return totalSizeOfRawData;
    }
    
    

}
