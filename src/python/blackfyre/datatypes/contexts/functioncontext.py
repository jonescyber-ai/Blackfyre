import hashlib
import os

from typing import Dict, List, Type, Optional

from blackfyre.util import setup_custom_logger
from blackfyre.common import ProcessorType, Endness, DisassemblerType
from blackfyre.datatypes.contexts.bbcontext import BasicBlockContext

logger = setup_custom_logger(os.path.splitext(os.path.basename(__file__))[0])


class FunctionContext(object):
    __slots__ = ['_name', '_start_address', '_end_address', '_segment_name', '_basic_block_context_dict', '_is_thunk',
                 '_string_ref_dict', '_callers', '_callees', '_size', '_proc_type', '_sha_256_hash', '_endness',
                 '_word_size', '_disassembler_type', '_language_id', '_total_instructions', '_decompiled_code']

    def __init__(self,
                 name: str,
                 start_address: int,
                 end_address: int,
                 segment_name: str,
                 basic_block_contexts: List[BasicBlockContext],
                 is_thunk: bool,
                 string_ref_dict: Dict[int, str],
                 callers: List[int],
                 callees: List[int],
                 proc_type: ProcessorType,
                 endness: Endness,
                 word_size: int,
                 disassembler_type: DisassemblerType,
                 language_id: str,
                 total_instructions: int,
                 decompiled_code: str) -> None:

        # Basic information about the function
        self._name: str = name
        self._start_address: int = start_address
        self._end_address: int = end_address
        self._size: int = end_address - start_address
        self._segment_name: str = segment_name

        # Thunk information
        self._is_thunk: bool = is_thunk

        # Processor and architecture details
        self._proc_type: ProcessorType = proc_type
        self._endness: Endness = endness
        self._word_size: int = word_size

        # Disassembler and language information
        self._disassembler_type: DisassemblerType = disassembler_type
        self._language_id: str = language_id

        # Instruction and code details
        self._total_instructions: int = total_instructions
        self._decompiled_code: str = decompiled_code

        # Basic block contexts
        self._basic_block_context_dict: Dict[int, BasicBlockContext] = {
            block.start_address: block for block in basic_block_contexts
        }

        # Function references and calls
        self._string_ref_dict: Dict[int, str] = string_ref_dict
        self._callers: List[int] = callers
        self._callees: List[int] = callees

        # SHA-256 hash (initially None, can be computed later)
        self._sha_256_hash: Optional[str] = None

    def get_basic_block(self, bb_addr) -> Optional[BasicBlockContext]:

        if bb_addr not in self._basic_block_context_dict:
            return None

        return self._basic_block_context_dict[bb_addr]

    @classmethod
    def from_pb(cls, function_context_pb, string_ref_dict=None, caller_to_callees_map=None, callee_to_callers_map=None,
                endess=None, word_size=None, disassembler_type=None, language_id=None):
        name = function_context_pb.name

        start_address = function_context_pb.start_address

        end_address = function_context_pb.end_address

        segment_name = function_context_pb.segment_name

        is_thunk = function_context_pb.is_thunk

        proc_type = ProcessorType(function_context_pb.proc_type)

        decompiled_code = function_context_pb.decompiled_code

        total_instructions = function_context_pb.total_instructions

        callers = callee_to_callers_map[start_address] if start_address in callee_to_callers_map else []

        callees = caller_to_callees_map[start_address] if start_address in caller_to_callees_map else []

        basic_block_contexts = [BasicBlockContext.from_pb(basic_block_context_pb)
                                for basic_block_context_pb in function_context_pb.basic_block_context_list]

        function_context = cls(name, start_address, end_address, segment_name, basic_block_contexts, is_thunk,
                               string_ref_dict, callers, callees, proc_type, endess, word_size, disassembler_type,
                               language_id, total_instructions, decompiled_code)

        return function_context

    @property
    def name(self) -> str:
        return self._name

    @property
    def address(self) -> int:
        return self._start_address

    @property
    def start_address(self) -> int:
        return self._start_address

    @property
    def end_address(self) -> int:
        return self._end_address

    @property
    def size(self) -> int:
        return self._size

    @property
    def is_thunk(self) -> bool:
        return self._is_thunk

    @property
    def string_ref_dict(self) -> Dict[int, str]:
        return self._string_ref_dict

    @property
    def basic_block_context_dict(self) -> Dict[int, BasicBlockContext]:
        return self._basic_block_context_dict

    @property
    def basic_block_contexts(self) -> List[BasicBlockContext]:
        for key in sorted(self._basic_block_context_dict.keys()):
            yield self._basic_block_context_dict[key]

    @property
    def callers(self) -> List[int]:
        return self._callers

    @property
    def callees(self) -> List[int]:
        """
        Returns the list of callees for this function. A callee (in this context) is a function defined within the binary
        that is directly called by this function. This excludes any indirect calls to external functions made
        through function pointers. If this function is a thunk (a small wrapper function that calls an external function),
        the callees will be the  functions that the thunk calls.
        """
        return self._callees

    @property
    def entry_basic_block_context(self) -> BasicBlockContext:
        return self.basic_block_context_dict[self.start_address]

    @property
    def endness(self) -> Endness:
        return self._endness

    @property
    def num_basic_blocks(self) -> int:
        return len(self.basic_block_context_dict)

    @property
    def proc_type(self) -> ProcessorType:
        return self._proc_type

    @property
    def sha_256_hash(self) -> str:
        if self._sha_256_hash is None:
            # Get the mnemonic list  based on the instruction address descending.
            mnemonics = [instruction_context.mnemonic.encode()
                         for basic_block_context in self.basic_block_contexts
                         for instruction_context in basic_block_context.native_instruction_contexts]
            mnemonic_bytes = b"".join(mnemonics)

            # compute the hash
            m = hashlib.sha256()
            m.update(mnemonic_bytes)
            self._sha_256_hash = m.hexdigest()

        return self._sha_256_hash

    @property
    def word_size(self) -> int:
        return self._word_size

    @property
    def disassembler_type(self) -> DisassemblerType:
        return self._disassembler_type

    @property
    def language_id(self) -> str:
        return self._language_id

    @property
    def decompiled_code(self) -> str:
        return self._decompiled_code

    @property
    def total_instructions(self) -> int:
        return self._total_instructions
