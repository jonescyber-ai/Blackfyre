import os
from typing import Optional, List

from blackfyre.common import PICKLE_EXT, IRCategory
from blackfyre.utils import setup_custom_logger
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.datatypes.contexts.vex.vexbbcontext import VexBasicBlockContext
from blackfyre.datatypes.contexts.vex.vexfunctioncontext import VexFunctionContext
from blackfyre.datatypes.contexts.vex.vexinstructcontext import VexInstructionContext
from blackfyre.datatypes.headers.peheader import PEHeader

logger = setup_custom_logger(os.path.splitext(os.path.basename(__file__))[0])


class VexBinaryContext(BinaryContext):
    __slots__ = []  # Since we are not adding attributes for the child class, the slot for the child is empty

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def call_target_from_vex_bb_context( self, vex_bb_context: VexBasicBlockContext) -> Optional[int]:
        """
        Return the call target for a VEX basic block, if one can be identified.

        The function first checks for a direct call instruction within the
        instruction contexts. If none is found, it attempts to resolve a tail call
        by examining the IRSB's jumpkind and constant `next` expression. Only
        constant targets that match known functions or imports are considered valid.

        Parameters
        ----------
        vex_bb_context : VexBasicBlockContext
            The VEX basic block context to analyze.

        Returns
        -------
        Optional[int]
            The resolved call target address, or ``None`` if no target is found.
        """

        # Check for a direct call in the instruction contexts.
        for instr_ctx in vex_bb_context.vex_instruction_contexts:
            if instr_ctx.category is IRCategory.call:
                call_target = instr_ctx.call_target_addr
                if call_target is None:
                    logger.debug("Call instruction has no call_target_addr.")
                    return None

                logger.debug("Direct call target address: 0x%x", call_target)
                return call_target

        # Fall back to tail-call resolution.
        irsb = vex_bb_context.irsb
        if irsb is None:
            logger.debug("No IRSB; cannot resolve tail call.")
            return None

        if getattr(irsb, "jumpkind", None) != "Ijk_Boring":
            return None

        next_expr = getattr(irsb, "next", None)
        if next_expr is None or getattr(next_expr, "tag", None) == "Iex_RdTmp":
            return None

        try:
            target = next_expr.constants[0].value
        except (AttributeError, IndexError):
            logger.debug("IRSB.next is not a direct constant.")
            return None

        if target in self.function_context_dict:
            logger.debug("Tail-call target resolved to known function: 0x%x", target)
            return target

        if target in self.import_symbol_dict:
            logger.debug("Tail-call target resolved to known import: 0x%x", target)
            return target

        logger.debug("Unrecognized tail-call target: 0x%x", target)
        return None

    def branch_targets_from_vex_bb_context(
            self,
            vex_bb_context: VexBasicBlockContext
    ) -> List[int]:
        """
        Return all branch-like targets that lie within the same function as the given VEX basic block.

        This includes:
          - “normal” control-flow branches (IRCategory.branch)
          - the fall-through address after a call (Ijk_Call), i.e., next instruction

        Process
        -------
        1. Determine containing function:
           The basic block address is checked against all function contexts.
           If multiple functions overlap, the most specific one is selected—
           defined as the function with the highest ``start_address`` that still
           contains the block.

        2. Collect valid targets:
           For each instruction in the basic block:
             * If its category is IRCategory.branch, use ``instr_ctx.jump_target_addr``.
             * If its jumpkind is ``Ijk_Call``, compute the fall-through address
               as ``native_address + native_instruction_size``.
           In both cases, the target is kept only if it is an integer within the
           function’s [start_address, end_address) range and not a duplicate.

        Returns
        -------
        List[int]
            Branch/fall-through targets that remain within the same function as the basic block.
        """

        bb_addr = vex_bb_context.start_address

        # Find the function containing this basic block (prefer most specific if overlapping).
        current_func_ctx = None
        for func_ctx in self.function_contexts:
            if func_ctx.start_address <= bb_addr < func_ctx.end_address:
                if current_func_ctx is None or func_ctx.start_address > current_func_ctx.start_address:
                    current_func_ctx = func_ctx

        if current_func_ctx is None:
            logger.debug("No function for basic block at 0x%x", bb_addr)
            return []

        func_start = current_func_ctx.start_address
        func_end = current_func_ctx.end_address
        logger.debug(
            "Basic block 0x%x in function [0x%x, 0x%x)",
            bb_addr,
            func_start,
            func_end,
        )

        targets: List[int] = []
        seen: set[int] = set()

        for instr_ctx in vex_bb_context.vex_instruction_contexts:
            target = None

            # Case 1: normal branch (your original logic)
            if instr_ctx.category is IRCategory.branch:
                target = instr_ctx.jump_target_addr

            # Case 2: call – add fall-through address as a branch target
            # (next instruction after the call)
            elif getattr(instr_ctx, "jumpkind", None) == "Ijk_Call":
                curr_address = instr_ctx.native_address
                native_instruction_size = instr_ctx.native_instruction_size
                target = curr_address + native_instruction_size

            if (
                    isinstance(target, int)
                    and target not in seen
                    and func_start <= target < func_end
            ):
                logger.debug("Intra-function branch/fall-through target: 0x%x", target)
                seen.add(target)
                targets.append(target)

        return targets

    @classmethod
    def get_pickle_file_path(cls, cache_path, binary_name):
        return os.path.join(cache_path, f"{binary_name}.vex.{PICKLE_EXT}")

    @classmethod
    def _get_function_context_from_pb(cls, func_context_pb, func_string_ref,
                                      caller_to_callees_map, callee_to_callers_map,
                                      endness, word_size, disassembler_type, language_id):
        """
        Overloads the parent class with a VexFunctionContext (versus FunctionContext)
        """

        return VexFunctionContext.from_pb(func_context_pb, func_string_ref,
                                          caller_to_callees_map, callee_to_callers_map, endness,
                                          word_size, disassembler_type, language_id)
