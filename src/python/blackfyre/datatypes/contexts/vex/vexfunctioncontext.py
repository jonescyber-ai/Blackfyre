import binascii
import logging
import os
import pdb

import pyvex
import archinfo
from typing import List, Dict, Type, Optional

from blackfyre.datatypes.contexts.vex.vexinstructcontext import VexInstructionContext
from blackfyre.util import setup_custom_logger
from blackfyre.common import ProcessorType, ArchWordSize, Endness, IRCategory
from blackfyre.datatypes.contexts.functioncontext import FunctionContext
from blackfyre.datatypes.contexts.nativeinstructcontext import NativeInstructionContext
from blackfyre.datatypes.contexts.vex.vexbbcontext import VexBasicBlockContext

logger = setup_custom_logger(os.path.splitext(os.path.basename(__file__))[0])


class VexFunctionContext(FunctionContext):
    # Notes on inheritance of slots: https://stackoverflow.com/questions/1816483/how-does-inheritance-of-slots-in-subclasses-actually-work
    __slots__ = ['_is_initialized', '_arch', '_all_callees', '_all_callee_call_sites', '_num_all_call_sites']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._is_initialized = False

        self._arch = self.get_arch()

        # List of all callees, includes pointers to external functions
        self._all_callees = None

        # Mapping of all call sites to callees, including unknown callee addresses
        self._all_callee_call_sites: Optional[Dict[Optional[int], List[int]]] = None

        # Number of all call sites, including those with unknown callee addresses
        self._num_all_call_sites = None

    def initialize(self):
        if self._is_initialized:
            return self._is_initialized

        self._generate_vex_basic_block_contexts()

        self._is_initialized = True

    def _generate_vex_basic_block_contexts(self):

        logger.debug("Generating blocks for Function: {}".format(self.name))

        vex_basic_block_context_dict: Dict[int, VexBasicBlockContext] = {}

        basic_block_context: Type[VexBasicBlockContext]
        for key, basic_block_context in self._basic_block_context_dict.items():

            instruction_context_list: List[NativeInstructionContext] = []

            for instruction_context in basic_block_context.native_instruction_contexts:

                logger.debug(
                    "[0x{0:x}] Opcode bytes: '{1}' size: '{2} mnemonic: '{3}'".format(instruction_context.address,
                                                                                      binascii.hexlify(bytearray(
                                                                                          instruction_context.opcode_bytes)),
                                                                                      instruction_context.size,
                                                                                      instruction_context.mnemonic))

                if self._is_repeatable_inst(instruction_context.mnemonic):

                    # Repeatable instructions need to be its own basic block so that they
                    # can jump back to themselves or jump to the next instruction that follows.

                    # Therefore, we'll wrap up the current irsb. That way the repeatable instructions will start
                    # at the start of a new irsb

                    # ****Wrap up the current irsb if previous instructions have been placed in it****
                    if len(instruction_context_list) > 0:
                        irsb = self._generate_irsb(instruction_context_list, self.arch)

                        # Create the BlockNode that houses the irsb object
                        vex_bb_context = VexBasicBlockContext(instruction_context_list, irsb, self.arch, self.proc_type)

                        # Add the block to block map
                        vex_basic_block_context_dict[instruction_context_list[0].address] = vex_bb_context

                    # *****Create an irsb soley for this repeatable instruction****
                    logger.debug("vex irsb start address 0x{0:x}".format(instruction_context.address))
                    irsb = self._generate_irsb([instruction_context], self.arch)

                    # Create the BlockNode that houses the irsb object
                    vex_bb_context = VexBasicBlockContext([instruction_context], irsb, self.arch, self.proc_type)

                    # Add the block to block map
                    vex_basic_block_context_dict[instruction_context.address] = vex_bb_context

                    # ****Reset the vex irsb elements since we will now began building a new irsb*****
                    instruction_context_list = []

                    continue

                if len(instruction_context_list) <= 0:
                    # instruction_context_list = [instruction_context]

                    logger.debug("vex irsb start address 0x{0:x}".format(instruction_context.address))

                instruction_context_list.append(instruction_context)

                if self._is_a_unconditional_branch_mnemonic(instruction_context.mnemonic):
                    # End of the irsb because this instruction is an unconditional branch
                    irsb = self._generate_irsb(instruction_context_list, self.arch)

                    # Create the BlockNode that houses the irsb object
                    vex_bb_context = VexBasicBlockContext(instruction_context_list, irsb, self.arch, self.proc_type)

                    # Add the block to block map
                    vex_basic_block_context_dict[instruction_context_list[0].address] = vex_bb_context

                    # Reset the vex irsb elements since we will now began building a new irsb
                    instruction_context_list = []

                    continue

            # Check if we need to create another irsb
            # Note: This occurs if the dis_basicblock does not terminate with a unconditional
            #       branch or return instruction
            if len(instruction_context_list) > 0:
                irsb = self._generate_irsb(instruction_context_list, self.arch)

                # Create the BlockNode that houses the irsb object
                vex_bb_context = VexBasicBlockContext(instruction_context_list, irsb, self.arch, self.proc_type)

                # Add the block to block map
                vex_basic_block_context_dict[instruction_context_list[0].address] = vex_bb_context

        self._basic_block_context_dict = vex_basic_block_context_dict

    # **************************** Helper Functions ***************************************

    def get_arch(self):

        # Arch information
        self._arch = None
        if self._proc_type == ProcessorType.x86_64:

            # AMD 64
            self._arch = archinfo.ArchAMD64()

        elif self._proc_type == ProcessorType.x86:

            self._arch = archinfo.ArchX86()

        elif self._proc_type == ProcessorType.ARM:

            self._arch = archinfo.ArchARM()

        elif self._proc_type == ProcessorType.AARCH64:

            self._arch = archinfo.ArchARM()

        elif self._proc_type == ProcessorType.MIPS and self._word_size == ArchWordSize.BITS_32:

            arch_endness = archinfo.Endness.BE
            if self._endness == Endness.LITTLE_ENDIAN:
                arch_endness = archinfo.Endness.LE

            self._arch = archinfo.ArchMIPS32(arch_endness)

        elif self._proc_type == ProcessorType.PPC and self._word_size == ArchWordSize.BITS_32:

            arch_endness = archinfo.Endness.BE
            if self._endness == Endness.LITTLE_ENDIAN:
                arch_endness = archinfo.Endness.LE

            self._arch = archinfo.ArchPPC32(arch_endness)

        elif self._proc_type == ProcessorType.PPC and self._word_size == ArchWordSize.BITS_64:

            arch_endness = archinfo.Endness.BE
            if self._endness == Endness.LITTLE_ENDIAN:
                arch_endness = archinfo.Endness.LE

            self._arch = archinfo.ArchPPC64(arch_endness)

        elif self._proc_type == ProcessorType.MIPS and self._word_size == ArchWordSize.BITS_64:

            arch_endness = archinfo.Endness.BE
            if self._endness == Endness.LITTLE_ENDIAN:
                arch_endness = archinfo.Endness.LE
            self._arch = archinfo.ArchMIPS64(arch_endness)

        else:
            raise ValueError("Unsupported architecture: '{}'".format(self._proc_type))

        return self._arch

    def get_all_callee_call_sites(self) -> Dict[Optional[int], List[int]]:
        """
        Analyze the function to identify all call targets and the specific addresses within the function where
        these calls occur, including cases where the call target is unknown.

        This method iterates through all the basic blocks and instructions in the function to extract both direct
        calls to internal functions and indirect calls via jumps (e.g., through function pointers). It returns
        a comprehensive mapping that details where each call occurs within the function's code.

        The result is a dictionary where:
            - The keys represent the addresses of the callee functions (i.e., the targets of the calls).
            - The value `None` or a placeholder represents calls where the target address is unknown.
            - The values are lists of addresses within the current function where these calls are made.

        Additionally, it includes the `self.callees`, which is a list of unique callee addresses within the function,
        but without specific call site information.

        This allows for tracking all call sites, even when the target function cannot be determined, while also
        providing a comprehensive list of callee addresses.

        Returns:
            Dict[Optional[int], List[int]]: A dictionary mapping each callee's address to a list of call site addresses
            within the function. The key `None` represents calls where the callee address is unknown.
        """
        call_targets: Dict[Optional[int], List[int]] = {}

        # Iterate through all basic block contexts and gather call sites
        for bb_context in self.basic_block_contexts:
            for vex_instruction_context in bb_context.vex_instruction_contexts:
                if vex_instruction_context.category == IRCategory.call:
                    call_target_addr = vex_instruction_context.call_target_addr
                    call_site_addr = vex_instruction_context.native_address

                    if call_target_addr not in call_targets:
                        call_targets[call_target_addr] = []

                    call_targets[call_target_addr].append(call_site_addr)

                elif vex_instruction_context.category == IRCategory.branch:
                    jump_target_addr = vex_instruction_context.jump_target_addr
                    call_site_addr = vex_instruction_context.native_address

                    if jump_target_addr is None:
                        continue

                    # Exclude the case where the jump is within the address range of the function
                    if self.start_address <= jump_target_addr <= self.end_address:
                        continue

                    if jump_target_addr not in call_targets:
                        call_targets[jump_target_addr] = []

                    call_targets[jump_target_addr].append(call_site_addr)

        # Ensure all callees are included in the dictionary, even if no specific call site was found
        for callee in self.callees:
            if callee not in call_targets:
                call_targets[callee] = []

        return call_targets

    def _is_repeatable_inst(self, mnemonic):

        if isinstance(self.arch, archinfo.ArchX86) or isinstance(self.arch, archinfo.ArchAMD64):

            repeatable_mnemonics = ['ins', 'movs', 'outs', 'lods', 'stos',
                                    'cmps', 'scas', 'movsb', 'movsw', 'movsd', 'movsq',
                                    'movsq', 'stosb', 'stosw', 'stosd', 'stosq',
                                    'cmpsb', 'cmpsw', 'cmpsd', 'cmpsq'
                                                               'scasb', 'scasw', 'scasd', 'scasq']

            if any(repeatable_mnemonic in mnemonic for repeatable_mnemonic in repeatable_mnemonics):
                return True

            elif "xchg" == mnemonic:

                """ The vex implementation of the xchg has a conditional branch to the top of the same address.
                    We need to create a new  basic block for  xchg instruction similar to the REP instruction
                    Here is an example:
                    
                    06 | ------ IMark(0x401482, 3, 0) ------
                       07 | t5 = GET:I64(rbx)
                       08 | t3 = LDle:I64(t5)
                       09 | t(6,4294967295) = CASle(t5 :: (t3,None)->(0x0000000000000000,None))
                       10 | t15 = CasCmpNE64(t6,t3)
                       11 | if (t15) { PUT(rip) = 0x401482; Ijk_Boring }
                       12 | PUT(rax) = t3
                       13 | ------ IMark(0x401485, 5, 0) ------
                       NEXT: PUT(rip) = 0x000000000040125d; Ijk_Boring             
                """
                return True

        return False

    @staticmethod
    def _is_plt(segment_name):

        if segment_name in ['.idata', '.plt', '.plt.got', '.plt.sec']:

            return True

        elif segment_name in ['.text', '.data', '.init', '.fini', 'EXTERNALS', 'EXTERNAL']:

            return False

        else:
            logger.warning("Unsupported segment_name: {}".format(segment_name))
            return False
            # raise Exception("Unsupported segment_name: {}".format(segment_name))

    def _generate_irsb(self, instruction_contexts: List[NativeInstructionContext], arch: archinfo.Arch):

        irsb = None

        vex_irsb_opcode_bytes = b"".join([instruction.opcode_bytes for instruction in instruction_contexts])
        vex_irsb_start_address = instruction_contexts[0].address
        vex_irsb_num_instructions = len(instruction_contexts)
        vex_irsb_num_bytes = len(vex_irsb_opcode_bytes)

        try:

            # Create the irsb object
            irsb = pyvex.IRSB(data=vex_irsb_opcode_bytes,
                              mem_addr=vex_irsb_start_address,
                              arch=arch,
                              num_inst=vex_irsb_num_instructions,
                              num_bytes=vex_irsb_num_bytes)

            logger.debug("Irsb size: {}".format(irsb.size))

            # logger.debug(irsb._pp_str())

        except pyvex.errors.PyVEXError as ex:

            logger.error(ex, exc_info=True)
            # logger.warning("[0x{0:x}] Problem creating irsb with start address: {1}; \nRecovering from Pyvex.Error -->{2}"
            #                .format(vex_irsb_start_address,ex))

            # Since we had a problem generating the IRSB with supplied opcodes, we'll replace with the equivalent
            # byte length of nops
            # Problem likely hardware instructions that can't be emulated/virtualized
            irsb = self._generate_nop_irsb(vex_irsb_start_address, vex_irsb_num_bytes)

            logger.warning("Replacing problem opcode with nops of the same length as original opcode")
            logger.warning(irsb._pp_str())

        return irsb

    def _generate_nop_irsb(self, address, num_bytes):

        nopcode_bytes = ""
        num_inst = 0

        if address is None:
            address = 0x00

        if isinstance(self.arch, archinfo.ArchX86):

            nopcode_bytes = b"\x90" * num_bytes
            num_inst = num_bytes

        elif isinstance(self.arch, archinfo.ArchAMD64):

            nopcode_bytes = b"\x90" * num_bytes
            num_inst = num_bytes

        elif isinstance(self.arch, archinfo.ArchARM):

            if nopcode_bytes % 4 != 0:
                raise ValueError("Expected number of bytes should be a multiple of 4 for ARM")

            nopcode_bytes = b"\x00" * num_bytes
            num_inst = num_bytes

        elif isinstance(self.arch, archinfo.ArchMIPS32) or isinstance(self.arch, archinfo.ArchMIPS64):

            if nopcode_bytes % 4 != 0:
                raise ValueError("Expected number of bytes should be a multiple of 4 for ARM")

            nopcode_bytes = b"\x00" * num_bytes
            num_inst = num_bytes


        else:

            raise ValueError("Unsupported architecture: {}".format(repr(self.arch)))

        # Create the nop irsb object
        irsb = pyvex.IRSB(data=nopcode_bytes,
                          mem_addr=address,
                          arch=self.arch,
                          num_inst=num_inst,
                          num_bytes=num_bytes)

        return irsb

    def _is_a_unconditional_branch_mnemonic(self, mnemonic):

        if isinstance(self.arch, archinfo.ArchX86) or isinstance(self.arch, archinfo.ArchAMD64):

            if mnemonic in ['call', 'jmp']:
                return True

        elif isinstance(self.arch, archinfo.ArchARM):

            if mnemonic in ['bx', 'bl', 'b']:
                return True

        elif isinstance(self.arch, archinfo.ArchMIPS32) or isinstance(self.arch, archinfo.ArchMIPS64):

            if mnemonic in ['j', 'jr', 'jal', 'jalr']:
                return True

        elif isinstance(self.arch, archinfo.ArchPPC32) or isinstance(self.arch, archinfo.ArchPPC64):

            if mnemonic in ['b', 'bl', 'ba', 'blr']:
                return True

        else:
            raise ValueError("Unsupported architecture: {}".format(repr(self.arch)))

        return False

    @property
    def arch(self):
        return self._arch

    # Note on overiding properties: https://stackoverflow.com/questions/7019643/overriding-properties-in-python
    @FunctionContext.basic_block_contexts.getter
    def basic_block_contexts(self):
        self.initialize()
        for key in sorted(self._basic_block_context_dict.keys()):
            yield self._basic_block_context_dict[key]

    @FunctionContext.basic_block_context_dict.getter
    def basic_block_context_dict(self):
        self.initialize()
        return self._basic_block_context_dict

    @property
    def all_callee_call_sites(self) -> Dict[Optional[int], List[int]]:
        """
        Analyze the function to identify all call targets and the specific addresses within the function where
        these calls occur, including cases where the call target is unknown.


        Returns:
            Dict[Optional[int], List[int]]: A dictionary mapping each callee's address to a list of call site addresses
            within the function. The key `None` represents calls where the callee address is unknown.
        """
        if self._all_callee_call_sites is None:
            self._all_callee_call_sites = self.get_all_callee_call_sites()

        return self._all_callee_call_sites

    @property
    def all_callees(self) -> List[int]:
        """
        Returns a comprehensive list of callees for this function, including both direct calls and calls made via pointers.

        This list includes:
            - Functions defined within the binary that are directly called by this function.
            - Functions that are called indirectly through function pointers, including calls to external functions.
        """
        if self._all_callees is None:
            self._all_callees = list(self.all_callee_call_sites.keys())

        return self._all_callees

    @property
    def num_all_call_sites(self) -> int:
        """
        Computes and returns the total number of call sites for this function. A call site refers to an instruction
        within the function that initiates a transfer of control, typically by calling another function or performing
        a jump to a different address. This count includes:

        - Direct calls: Function calls where the target function is explicitly referenced in the code.
        - Indirect calls: Calls where the target function is determined at runtime, such as through function pointers.
        - Jumps: Control flow instructions that transfer execution to a different address, including those where the
          target address lies outside the function's address range.

        The method counts all call sites detected within the function, even if the target address of a jump is outside
        the function's address range.

        Notes:
        - The method may undercount the actual number of call sites in cases where the jump target cannot be determined
          statically. For example, this might occur with indirect jumps, where the target is resolved only at runtime.
        - Additionally, the method might undercount call sites when jumps target addresses within the function's own
          address range, as it might not account for calls to functions located within the same function.
        - If a callee does not have any specific call sites associated with it (i.e., the list of call sites for that callee
          is empty), it is counted as a single call site.

        Returns:
            int: The total number of call sites detected for this function, including direct calls, indirect calls, and jumps.
        """
        if self._num_all_call_sites is None:
            self._num_all_call_sites = 0
            for callee in self.all_callee_call_sites:
                num_call_sites = len(self.all_callee_call_sites[callee])

                if num_call_sites == 0:
                    # If the callee has no specific call site, count it as a single call site
                    self._num_all_call_sites += 1
                else:
                    self._num_all_call_sites += num_call_sites

        return self._num_all_call_sites

