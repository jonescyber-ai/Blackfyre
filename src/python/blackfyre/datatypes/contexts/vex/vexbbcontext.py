import os
import re
from typing import List, Dict, Optional

import archinfo
import pyvex

from blackfyre.util import setup_custom_logger
from blackfyre.common import ProcessorType, IRCategory, BasicBlockExitType
from blackfyre.datatypes.contexts.bbcontext import BasicBlockContext
from blackfyre.datatypes.contexts.nativeinstructcontext import NativeInstructionContext
from blackfyre.datatypes.contexts.vex.vexinstructcontext import VexInstructionContext

logger = setup_custom_logger(os.path.splitext(os.path.basename(__file__))[0])


class VexBasicBlockContext(BasicBlockContext):
    __slots__ = ["_arch", "_irsb", "_exit_type"]

    def __init__(self,
                 instruction_contexts: List[NativeInstructionContext],
                 irsb: pyvex.IRSB,
                 arch: archinfo.Arch,
                 proc_type: ProcessorType):

        start_address = instruction_contexts[0].address

        opcode_bytes = b"".join([instruction.opcode_bytes for instruction in instruction_contexts])

        size = len(opcode_bytes)

        end_address: int = start_address + size

        self._arch: archinfo.Arch = arch

        self._irsb: pyvex.IRSB = irsb

        self._exit_type: Optional[BasicBlockExitType] = None

        super().__init__(start_address, end_address, instruction_contexts, proc_type)

    @property
    def next_basic_block_address(self):

        next_basic_block_address = None

        irsb = self._irsb

        if irsb.jumpkind == "Ijk_Boring":

            if irsb.next.tag != "Iex_RdTmp":
                next_basic_block_address = irsb.next.constants[0].value

        return next_basic_block_address

    @staticmethod
    def _get_instruction_size_from_IMark(imark_string):

        p = re.compile(r'.*IMark\(0x([0-9a-f]*),.*(\d)+,')
        m = p.match(imark_string)

        assert m is not None, "Failed to parse Imark string {}".format(imark_string)

        instruction_size = int(m.group(2))

        return instruction_size

    @staticmethod
    def _get_address_from_IMark(imark_string):

        p = re.compile(r'.*IMark\(0x([0-9a-f]*),.*(\d)+,')
        m = p.match(imark_string)

        assert m is not None, "Failed to parse Imark string {}".format(imark_string)

        # Instruction address is in the first regex group
        instruction_address = int(m.group(1), 16)

        return instruction_address

    @property
    def arch(self):
        return self._arch

    @property
    def irsb(self):
        return self._irsb

    @property
    def exit_type(self) -> BasicBlockExitType:
        """
        Determines the exit type of this basic block by examining instruction categories.
        Returns RETURN if any instruction has IRCategory.ret,
        NON_TERMINALf any instruction has IRCategory.call,
        otherwise UNKNOWN_TERMINAL.
        Result is cached after first computation.
        """
        if self._exit_type is None:
            for instr_ctx in self.vex_instruction_contexts:
                if instr_ctx.category == IRCategory.ret:
                    self._exit_type = BasicBlockExitType.RETURN
                    break
                elif instr_ctx.category == IRCategory.call:
                    self._exit_type = BasicBlockExitType.NON_TERMINAL
                    break
            else:
                self._exit_type = BasicBlockExitType.UNKNOWN_TERMINAL

        return self._exit_type

    @property
    def vex_instruction_contexts(self):

        curr_native_instr_address = 0x0
        curr_native_instr_size = 0x0

        # Key is the tmp register index and the value is the constant value
        temp_register_dict: Dict[int, int] = {}

        for stmt in self._irsb.statements:

            # ** AbiHint **
            if isinstance(stmt, pyvex.stmt.AbiHint):

                # Do nothing with this statement
                pass

            # ** IMark **
            elif isinstance(stmt, pyvex.stmt.IMark):

                # IMark maps this current vex statement to the associated native instruction
                imark_string = str(stmt)

                # Set the current native instruction that the vex ir is associated with
                curr_native_instr_address = self._get_address_from_IMark(imark_string)

                # Set the current native instruction size that the vex ir is associated with
                curr_native_instr_size = self._get_instruction_size_from_IMark(imark_string)

            else:
                # Store the tmp register index and the constant value in a dictionary
                if isinstance(stmt, pyvex.stmt.WrTmp):

                    tmp_register_index: int = stmt.tmp

                    # Check if the constants are defined
                    if len(stmt.data.constants) > 0:
                        constant = stmt.data.constants[0]
                        constant_value = constant.value
                        temp_register_dict[tmp_register_index] = constant_value

                yield VexInstructionContext(stmt, curr_native_instr_address, curr_native_instr_size, temp_register_dict)
        else:
            yield VexInstructionContext(self._irsb, curr_native_instr_address, curr_native_instr_size,
                                        temp_register_dict)
