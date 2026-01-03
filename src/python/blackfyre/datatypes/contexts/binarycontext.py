import hashlib
import os.path
import pickle
import zlib
from hashlib import sha256
from pathlib import Path
from typing import Dict, List, Type, Optional

import numpy as np

from blackfyre.datatypes.defineddata import DefinedData
from blackfyre.datatypes.exportsymbol import ExportSymbol
from blackfyre.util import get_message_type, get_message_size, setup_custom_logger, mkdir_p
from blackfyre.common import DisassemblerType, ProcessorType, FileType, ArchWordSize, Endness, \
    BINARY_CONTEXT_CONTAINER_EXT, DEFAULT_CACHE_DIR, PICKLE_EXT
from blackfyre.datatypes.contexts.bbcontext import BasicBlockContext
from blackfyre.datatypes.contexts.functioncontext import FunctionContext
from blackfyre.datatypes.contexts.nativeinstructcontext import NativeInstructionContext
from blackfyre.datatypes.headers.header import Header
from blackfyre.datatypes.headers.peheader import PEHeader
from blackfyre.datatypes.importsymbol import ImportSymbol
from blackfyre.datatypes.protobuf import binary_context_pb2, function_context_pb2

logger = setup_custom_logger(os.path.splitext(os.path.basename(__file__))[0])


# logger.setLevel(logging.DEBUG)

# logger = logging.getLogger("binarycontext")
# logging.basicConfig(level=logging.INFO)
# logger.setLevel(logging.INFO)

class BinaryContext(object):
    __slots__ = ['_name', '_sha256_hash', '_proc_type', '_file_type', '_word_size', '_endness', '_import_symbols',
                 '_string_refs', '_language_id', '_total_functions', '_disassembler_type', '_function_context_dict',
                 '_caller_to_callees_map', '_callee_to_callers_map', '_header', '_raw_binary_file_bytes',
                 '_defined_data_map', '_total_instructions', '_import_symbol_dict',
                 '_export_symbols', '_export_symbol_dict', '_file_size', '_disassembler_version', '_bcc_version']

    def __init__(self, name:str, sha256_hash, proc_type, file_type, word_size, endness, import_symbols,
                 string_refs: Dict[int, str], language_id, total_functions, disassembler_type,
                 caller_to_callees_map, callee_to_callers_map, defined_data_map: Dict[int, DefinedData],
                total_instructions: int,export_symbols,file_size ,header=None,
                 function_context_dict: Dict[int, Type[FunctionContext]] = None, raw_binary_file=None,
                 disassembler_version=None, bcc_version=None):

        # Binary Name
        self._name: str = name

        # SHA-256 Hash
        self._sha256_hash: str = sha256_hash

        # Processor Type (e.g. x86, ARM, etc..)
        self._proc_type: ProcessorType = proc_type

        # File Type (e.g. elf, PE,etc..)
        self._file_type: FileType = file_type

        # Word Size (e.g. 32-bit vs 64-bit)
        self._word_size: ArchWordSize = word_size

        # Endness (e.g. Big endian vs little endian)
        self._endness: Endness = endness

        # Import symbol list
        self._import_symbols: List[ImportSymbol] = import_symbols

        # Import symbol dictionary (key is the address where the import symbol is located in the binary)
        self._import_symbol_dict: Dict[int, ImportSymbol] = {import_symbol.address: import_symbol
                                                             for import_symbol in import_symbols}

        self._export_symbols: List[ExportSymbol] = export_symbols

        self._export_symbol_dict: Dict[int, ExportSymbol] = {export_symbol.address: export_symbol for export_symbol in export_symbols}

        # String References
        self._string_refs: Dict[int, str] = string_refs

        # Disassembler Language ID (e.g. Ghidra --> "ARM:LE:64:v7")
        self._language_id: str = language_id

        # Total number of functions in the binary
        self._total_functions: int = total_functions

        # Disassembler Type (e.g. Ghidra, Binary, or Binary Ninja)
        self._disassembler_type: DisassemblerType = disassembler_type

        # Function Context dictionary ( [key:value]   address: FunctionContext)
        self._function_context_dict: Dict[int, Type[FunctionContext]] = function_context_dict

        # Caller to callees map ([key: caller address;  value: list of callee addresses )
        self._caller_to_callees_map: Dict[int, int] = caller_to_callees_map

        # Callee to callers map ([key: callee address;  value: list of caller addresses )
        self._callee_to_callers_map: Dict[int, int] = callee_to_callers_map

        # Header (e.g. PE Header)
        self._header: Header = header

        # Raw binary file
        self._raw_binary_file_bytes: bytes = raw_binary_file

        # Defined Data Map
        self._defined_data_map: dict[int, DefinedData] = defined_data_map

        # Total number of instructions in the binary
        self._total_instructions = total_instructions

        # File Size
        self._file_size = file_size

        # Disassembler Version
        self._disassembler_version = disassembler_version

        # BCC Version
        self._bcc_version = bcc_version

    def get_function_name(self, func_address: int, return_closest_function=False):

        # Returns the closes function name (by address) if the passed in address is not the entry point of the function
        if func_address not in self._function_context_dict and return_closest_function:
            def closest(lst, K):
                lst = np.asarray(lst)
                idx = (np.abs(lst - K)).argmin()
                return lst[idx]

            function_address_list = list(self._function_context_dict.keys())
            closest_func_address = closest(function_address_list, func_address)
            logger.debug(
                f"Attempting to get function, but the function entry is not at 0x{func_address:x} "
                f"Will return the closest function entry point name that occurs at  0x{closest_func_address:x}")
            func_address = closest_func_address

        return self._function_context_dict[func_address].name

    def get_function_context(self, func_address: int) -> Type[FunctionContext]:
        return self._function_context_dict[func_address]

    def get_import_symbol(self, address: int) -> Optional[ImportSymbol]:

        if address not in self._import_symbol_dict:
            return None

        return self._import_symbol_dict[address]

    @classmethod
    def _get_function_context_from_pb(cls, func_context_pb, func_string_ref,
                                      caller_to_callees_map, callee_to_callers_map, endness,
                                      word_size, disassembler_type, language_id):

        return FunctionContext.from_pb(func_context_pb, func_string_ref,
                                       caller_to_callees_map, callee_to_callers_map, endness,
                                       word_size, disassembler_type, language_id)

    # ===================================Helper Functions ========================================

    @classmethod
    def _build_function_context_dict(cls, message_bytes, byte_index, total_funcs, binary_string_ref,
                                     caller_to_callees_map, callee_to_callers_map, endness,
                                     word_size, disassembler_type, language_id):

        function_context_dict = {}
        message_size = 0
        for index in range(total_funcs):
            # [TYPE] Get the message type (First byte of message)
            byte_index += message_size
            message_type = get_message_type(message_bytes[byte_index:byte_index + 1])

            # [LENGTH] Get message size (Next four bytes of message)
            byte_index += 1
            message_size = get_message_size(message_bytes[byte_index:byte_index + 4])

            # [Value] The FunctionContext protobuf message
            byte_index += 4
            func_context_message = message_bytes[byte_index:byte_index + message_size]

            # Create the protobuf object
            func_context_pb = function_context_pb2.FunctionContext()

            # Populate the protobuf object from the message bytes
            func_context_pb.ParseFromString(func_context_message)

            # Build function string ref
            func_string_ref = {key: binary_string_ref[key] for key in binary_string_ref
                               if func_context_pb.start_address <= key <= func_context_pb.end_address}

            function_context = cls._get_function_context_from_pb(func_context_pb, func_string_ref,
                                                                 caller_to_callees_map, callee_to_callers_map, endness,
                                                                 word_size, disassembler_type, language_id)

            # Add the function context to the dictionary
            function_context_dict[function_context.start_address] = function_context

            logger.info(f"[{index + 1}/{total_funcs}] "
                        f"Loaded FunctionContext: (0x{function_context.start_address:x})"
                        f" {function_context.name} ")
        # Update the byte_index
        byte_index += message_size

        return (function_context_dict, byte_index)

    # ===================================END Helper Functions ========================================

    @classmethod
    def from_pb(cls, binary_context_pb):
        assert isinstance(binary_context_pb, binary_context_pb2.BinaryContext), \
            f"Expected a protobuf object of type 'binary_context_pb2.BinaryContext'"

        # Collect all the required attributes in a dictionary
        kwargs = {
            'name': binary_context_pb.name,
            'sha256_hash': binary_context_pb.sha256_hash,
            'proc_type': ProcessorType(binary_context_pb.proc_type),
            'file_type': FileType(binary_context_pb.file_type),
            'word_size': ArchWordSize(binary_context_pb.word_size),
            'endness': Endness(binary_context_pb.endness),
            'total_instructions': binary_context_pb.total_instructions,
            'file_size': binary_context_pb.file_size,
            'language_id': binary_context_pb.language_id if len(binary_context_pb.language_id) > 0 else None,
            'total_functions': binary_context_pb.total_functions,
            'disassembler_type': DisassemblerType(binary_context_pb.disassembler_type),
            'disassembler_version': binary_context_pb.disassembler_version,
            'bcc_version': binary_context_pb.bcc_version,
        }

        # Conditional handling for 'header'
        if kwargs['file_type'] in [FileType.PE32, FileType.PE64]:
            kwargs['header'] = PEHeader.from_pb(binary_context_pb.pe_header)
        else:
            kwargs['header'] = None

        # Lists and maps
        kwargs['import_symbols'] = [ImportSymbol.from_pb(import_symbol_pb)
                                    for import_symbol_pb in binary_context_pb.import_symbol_list]

        kwargs['export_symbols'] = [ExportSymbol.from_pb(export_symbol_pb)
                                    for export_symbol_pb in binary_context_pb.export_symbol_list]

        kwargs['caller_to_callees_map'] = {
            key: [callee for callee in binary_context_pb.caller_to_callees_map[key].callees]
            for key in binary_context_pb.caller_to_callees_map
        }

        kwargs['callee_to_callers_map'] = {
            key: [caller for caller in binary_context_pb.callee_to_callers_map[key].callers]
            for key in binary_context_pb.callee_to_callers_map
        }

        kwargs['string_refs'] = {
            key: binary_context_pb.string_refs[key]
            for key in binary_context_pb.string_refs
        }

        kwargs['defined_data_map'] = {
            key: DefinedData.from_pb(binary_context_pb.defined_data_map[key])
            for key in binary_context_pb.defined_data_map
        }

        # Create the instance using the collected keyword arguments
        binary_context = cls(**kwargs)

        return binary_context

    @classmethod
    def from_bytes(cls, binary_context_bytes, verify_sha_256_digest=True, load_raw_binary=False):
        # Note: FunctionContexts are not added into the BinaryContext protobuf because of size limits
        #       protobuf (~65 MB).  Therefore the FunctionContexts will reside in their individual
        #       protobuf message.  During serialization to bytes (i.e. toBytes()), the function context will
        #       be concatenated to the end of the BinaryContext protobuf message serialized bytes.
        #
        #       The TLV Format will be the following:
        #       Type (1  byte); Length (4 bytes); Value (message bytes)
        #
        #        The bytes will consist of the following:
        #           1. BinaryContext PB Message  [TLV]
        #           2. First FunctionFunction Context PB Message [TLV]
        #               ......
        #           N-1. Last Function Context PB Message [TLV]
        #           N  Sha-256 digest (32 bytes) of 1 through to N-1

        uncompress_bin_context_bytes = zlib.decompress(binary_context_bytes)

        if verify_sha_256_digest:

            # Digest is the last 32 bytes of the message
            digest = uncompress_bin_context_bytes[-32:]

            # Message without the digest
            message_byte = uncompress_bin_context_bytes[:-32]

            computed_digest = sha256(message_byte).digest()

            if digest != computed_digest:
                raise Exception(f"Expected digest does not match the computed digest:\n"
                                f"(expected) {digest} != (computed) {computed_digest}")

        # ************************** Binary Contexts  ****************************

        # ** Unpack the TLV data **

        # [TYPE] Get the message type (First byte of message)
        byte_index = 0
        message_type = get_message_type(uncompress_bin_context_bytes[byte_index:byte_index + 1])

        # [LENGTH] Get message size (Next four bytes of message)
        byte_index += 1
        message_size = get_message_size(uncompress_bin_context_bytes[byte_index:byte_index + 4])

        # [Value] The BinaryContext protobuf message
        byte_index += 4
        message = uncompress_bin_context_bytes[byte_index:byte_index + message_size]

        # Update the index to point to the next TLV (i.e. FunctionContext)
        byte_index += message_size

        # Create the protobuf object
        binary_context_pb = binary_context_pb2.BinaryContext()

        # Populate the protobuf object from the message bytes
        binary_context_pb.ParseFromString(message)

        # Create the binary context object from the protobuf message
        binary_context = cls.from_pb(binary_context_pb)

        # ************************** Function Contexts  ****************************

        total_funcs = binary_context.total_functions
        binary_string_refs = binary_context.string_refs
        caller_to_callees_map = binary_context.caller_to_callees_map
        callee_to_callers_map = binary_context.callee_to_callers_map
        endness = binary_context.endness
        word_size = binary_context.word_size
        disassembler_type = binary_context.disassembler_type
        language_id = binary_context.language_id

        (function_context_dict, byte_index) = cls._build_function_context_dict(uncompress_bin_context_bytes,
                                                                               byte_index,
                                                                               total_funcs,
                                                                               binary_string_refs,
                                                                               caller_to_callees_map,
                                                                               callee_to_callers_map,
                                                                               endness,
                                                                               word_size,
                                                                               disassembler_type,
                                                                               language_id)
        # Update the context with the function context dictionary
        binary_context._function_context_dict = function_context_dict

        # ************************** Raw Binary  ****************************
        # ** Unpack the TLV data **

        if load_raw_binary:

            # [TYPE] Get the message type (First byte of message)
            message_type = get_message_type(uncompress_bin_context_bytes[byte_index:byte_index + 1])

            # [LENGTH] Get message size (Next four bytes of message)
            byte_index += 1
            message_size = get_message_size(uncompress_bin_context_bytes[byte_index:byte_index + 4])

            # [Value] The BinaryContext protobuf message
            byte_index += 4
            message = uncompress_bin_context_bytes[byte_index:byte_index + message_size]

            if message_size == 0:
                logger.info("Optional raw binary is not present in the message")
            elif verify_sha_256_digest:
                # verify the raw binary hash
                m = hashlib.sha256()
                m.update(message)
                computed_raw_binary_hash = m.hexdigest()

                if binary_context.sha256_hash != computed_raw_binary_hash:
                    raise Exception(f"Raw binary sha-256 does not match the computed hash:"
                                    f"{binary_context.sha256_hash} (expected) != {computed_raw_binary_hash} (computed)")

                # Update binary context with the raw binary
                binary_context._raw_binary_file_bytes = message

        return binary_context

    @classmethod
    def get_pickle_file_path(cls, cache_path, binary_name):

        return os.path.join(cache_path, f"{binary_name}.{PICKLE_EXT}")

    @classmethod
    def load_from_file(cls, binary_context_file_path, verify_sha_256_digest=True, load_raw_binary=False,
                       cache_path=DEFAULT_CACHE_DIR):

        binary_name = None
        pickle_file_path = None
        if cache_path is not None:

            binary_name = Path(binary_context_file_path).stem
            pickle_file_path = cls.get_pickle_file_path(cache_path, binary_name)

            # Check if the pickle path exists
            if os.path.exists(pickle_file_path):

                try:
                    logger.info(f"Found cache pickled binary context  for '{binary_name}'")
                    binary_context = pickle.load(open(pickle_file_path, "rb"))
                    return binary_context
                except (EOFError, pickle.UnpicklingError):
                    logger.exception(
                        f"problem loading cached binary context:'{pickle_file_path}'... Will load from file")

        binary_context_bytes = None
        with open(binary_context_file_path, "rb") as f:
            binary_context_bytes = f.read()

        binary_context = cls.from_bytes(binary_context_bytes, verify_sha_256_digest, load_raw_binary)

        logger.info(f"Loaded binary context from the following path:{binary_context_file_path}")

        # Cache the binary context if we have cache path
        if cache_path is not None:
            # make the cache path if it does not exist
            mkdir_p(cache_path)

            pickle.dump(binary_context, open(pickle_file_path, "wb"))
            logger.info(f"Cached binary context  for '{binary_name}'")

        return binary_context

    @classmethod
    def extract_raw_binary_to_file(cls, binary_context_file_path, extraction_folder_path):

        binary_context = cls.load_from_file(binary_context_file_path, True, True, cache_path=None)

        extraction_file_path = os.path.join(extraction_folder_path,
                                            f"{binary_context.name}_{binary_context.sha256_hash}")

        if binary_context._raw_binary_file_bytes is None:
            raise Exception("Optional Raw Binary was not included in the Binary Context Container file")

        with open(extraction_file_path, 'wb') as f:
            f.write(binary_context._raw_binary_file_bytes)

        logger.info(f"Extracted raw binary to the following path:{extraction_file_path}")

        pass

    @property
    def name(self):
        return self._name

    @property
    def base_name(self):
        """
         Removes the extension and version information
         libmyllib.so.1.2.3 == > libmylib
        """
        return self._name.split(".")[0]

    @property
    def sha256_hash(self):
        return self._sha256_hash

    @property
    def proc_type(self):
        return self._proc_type

    @property
    def file_type(self):
        return self._file_type

    @property
    def word_size(self):
        return self._word_size

    @property
    def endness(self):
        return self._endness

    @property
    def import_symbols(self):
        return self._import_symbols

    @property
    def import_symbol_dict(self):
        return self._import_symbol_dict

    @property
    def export_symbols(self):
        return self._export_symbols

    @property
    def string_refs(self):
        return self._string_refs

    @property
    def language_id(self):
        return self._language_id

    @property
    def total_functions(self):
        return self._total_functions

    @property
    def disassembler_type(self):
        return self._disassembler_type

    @property
    def function_context_dict(self) -> Dict[int, Type[FunctionContext]]:
        return self._function_context_dict

    @property
    def function_contexts(self):
        for key in sorted(self._function_context_dict.keys()):
            yield self._function_context_dict[key]

    @property
    def header(self):
        return self._header

    @property
    def caller_to_callees_map(self):
        return self._caller_to_callees_map

    @property
    def callee_to_callers_map(self):
        return self._callee_to_callers_map

    @property
    def defined_data_map(self):
        return self._defined_data_map

    @property
    def disassembler_version(self):
        return self._disassembler_version

    @property
    def bcc_version(self):
        return self._bcc_version

