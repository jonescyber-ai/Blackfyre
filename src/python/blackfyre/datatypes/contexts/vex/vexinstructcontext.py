import logging
import os
import re
from typing import Dict

import pyvex
from blackfyre.util import setup_custom_logger
from blackfyre.common import IRCategory
from blackfyre.datatypes.contexts.irinstructcontext import IRInstructionContext

logging.getLogger("pyvex.expr").setLevel(logging.WARNING)

logger = setup_custom_logger(os.path.splitext(os.path.basename(__file__))[0])


class VexInstructionContext(IRInstructionContext):
    __slots__ = ["_temp_register_dict"]

    def __init__(self,
                 statement,
                 native_address:int,
                 native_instruction_size: int,
                 temp_register_dict: Dict[int, int] = None):

        self._temp_register_dict = temp_register_dict

        super().__init__(statement, native_address, native_instruction_size)

    @property
    def call_target_addr(self):

        call_target = None

        if isinstance(self.instruction, pyvex.IRSB):

            irsb = self.instruction

            if irsb.jumpkind == "Ijk_Call":
                call_target = irsb.default_exit_target

                if call_target is None:
                    # Check if we can get the address from an indirect call target from a temp register
                    if irsb.next.tag == "Iex_RdTmp":

                        temp_register = irsb.next.tmp

                        if temp_register in self._temp_register_dict:

                            call_target = self._temp_register_dict[temp_register]

        return call_target

    @property
    def jump_target_addr(self):

        jump_target = None

        if isinstance(self.instruction, pyvex.IRSB):

            # Case where unconditional exit
            irsb = self.instruction
            if irsb.jumpkind == "Ijk_Boring" and irsb.next.tag != "Iex_RdTmp":
                jump_target = irsb.next.constants[0].value

            elif irsb.jumpkind == "Ijk_Call":

                # Since this is a call instruction, we compute the next instruction (i.e. jump target) to be
                # the current address + the size of the instruction
                curr_address = self.native_address
                native_instruction_size = self.native_instruction_size
                jump_target = curr_address + native_instruction_size


        elif isinstance(self.instruction, pyvex.stmt.Exit):
            # Case where conditional exit
            jump_target = self.instruction.dst.value

        return jump_target

    @staticmethod
    def _get_ir_category_from_statement(stmt):

        ir_category = IRCategory.other

        # ** Exit **
        if isinstance(stmt, pyvex.stmt.Exit):

            ir_category = IRCategory.branch

        # ** Put **
        elif isinstance(stmt, pyvex.stmt.Put):

            ir_category = IRCategory.reg_access

        # ** Store **
        elif isinstance(stmt, pyvex.stmt.Store):

            ir_category = IRCategory.store

        # ** WrTmp **
        elif isinstance(stmt, pyvex.stmt.WrTmp):

            # Get the expression
            expression_data = stmt.data

            # Get the ir category of this expression
            ir_category = VexInstructionContext._get_ir_category_from_expression(expression_data)

        elif isinstance(stmt, pyvex.block.IRSB):

            # unconditional exit
            ir_category = VexInstructionContext._get_ir_category_from_unconditional_exit_stmt(stmt)
            pass

        else:

            logger.debug(
                "Unsupported statement of type '{}'. Will default IR category to IRCategory.other".format(
                    type(stmt)))
            ir_category = IRCategory.other

        return ir_category

    @staticmethod
    def _get_mnemonic_from_statement(stmt):

        mnemonic = ""

        # ** Exit **
        if isinstance(stmt, pyvex.stmt.Exit):

            mnemonic = IRCategory.branch.name

        # ** Put **
        elif isinstance(stmt, pyvex.stmt.Put):

            mnemonic = stmt.tag.split("_")[1]

        # ** Store **
        elif isinstance(stmt, pyvex.stmt.Store):

            mnemonic = IRCategory.store.name

        # ** WrTmp **
        elif isinstance(stmt, pyvex.stmt.WrTmp):

            # Get the expression
            expression_data = stmt.data

            # Get the ir category of this expression
            mnemonic = VexInstructionContext._get_mnemonic_from_expression(expression_data)

        elif isinstance(stmt, pyvex.block.IRSB):

            # unconditional exit
            mnemonic = VexInstructionContext._get_ir_category_from_unconditional_exit_stmt(stmt).name
            pass

        elif isinstance(stmt, pyvex.stmt.MBE):

            mnemonic = stmt.tag.split("_")[1]
            pass

        else:
            mnemonic = stmt.tag.split("_")[1]

            pass

        return mnemonic

    @staticmethod
    def _get_ir_category_from_unconditional_exit_stmt(irsb):

        if irsb.jumpkind == "Ijk_Boring":

            return IRCategory.branch

        elif irsb.jumpkind == "Ijk_Call":

            return IRCategory.call

        elif irsb.jumpkind == "Ijk_Ret":

            return IRCategory.ret

        else:
            return IRCategory.other

    @staticmethod
    def _get_mnemonic_from_expression(expression_data):

        mnemonic = ""

        # Get the expression tag
        expression_tag = expression_data.tag

        # get the expression class from the expression tag
        expr_class = pyvex.expr.tag_to_expr_class(expression_tag)

        # Handle based on the expression class type and

        # ** Binop **
        if expr_class == pyvex.expr.Binop:

            mnemonic = expression_data.op.split("_")[1]

            # Remove the register size in the operand (e.g. ADD32 --> ADD)
            #mnemonic = re.sub(r"\d+", "", mnemonic)
            pass

        # ** Get **
        elif expr_class == pyvex.expr.Get:

            mnemonic = expression_data.tag.split("_")[1]

            pass

        # ** Load **
        elif expr_class == pyvex.expr.Load:

            mnemonic = expression_data.tag.split("_")[1]

        # ** RdTmp **
        elif expr_class == pyvex.expr.RdTmp:

            mnemonic = expression_data.tag.split("_")[1]

        # ** Unop **
        elif expr_class == pyvex.expr.Unop:

            mnemonic = VexInstructionContext._get_ir_category_from_unop(expression_data).name
            pass

        # ** CCall **
        elif expr_class == pyvex.expr.CCall:

            mnemonic = expression_data.tag.split("_")[1]

        elif expr_class == pyvex.expr.Const:

            mnemonic = IRCategory.other.name

        else:
            mnemonic = expression_data.tag.split("_")[1]

        return mnemonic

    @staticmethod
    def _get_ir_category_from_expression(expression_data):

        # Get the expression tag
        expression_tag = expression_data.tag

        # get the expression class from the expression tag
        expr_class = pyvex.expr.tag_to_expr_class(expression_tag)

        # The ir category that this expression falls under
        ir_category = IRCategory.other

        # Handle based on the expression class type and

        # ** Binop **
        if expr_class == pyvex.expr.Binop:

            ir_category = VexInstructionContext._get_ir_category_from_bin_op(expression_data)

        # ** Get **
        elif expr_class == pyvex.expr.Get:

            ir_category = IRCategory.reg_access

        # ** Load **
        elif expr_class == pyvex.expr.Load:

            ir_category = IRCategory.load

        # ** RdTmp **
        elif expr_class == pyvex.expr.RdTmp:

            ir_category = IRCategory.other

        # ** Unop **
        elif expr_class == pyvex.expr.Unop:

            ir_category = VexInstructionContext._get_ir_category_from_unop(expression_data)

        # ** CCall **
        elif expr_class == pyvex.expr.CCall:

            ir_category = IRCategory.other

        elif expr_class == pyvex.expr.Const:

            ir_category = IRCategory.other

        else:
            logger.debug(
                "Unsupported expression class '{}' Will default to IRCategory.other.".format(str(expr_class)))
            ir_category = IRCategory.other

        return ir_category

    @staticmethod
    def _get_ir_category_from_bin_op(bin_op_expr_data):

        # The ir category that this binary operation falls under
        ir_category = None

        bin_op = bin_op_expr_data.op

        if "Add" in bin_op:

            ir_category = IRCategory.arithmetic

        elif "And" in bin_op:

            ir_category = IRCategory.bit_logic

        elif "Sub" in bin_op:

            ir_category = IRCategory.arithmetic

        elif "Mul" in bin_op:

            ir_category = IRCategory.arithmetic

        elif "Cmp" in bin_op:

            ir_category = IRCategory.compare

        elif "Iop_Sh" in bin_op:

            ir_category = IRCategory.bit_shift

        elif "Or" in bin_op:

            ir_category = IRCategory.bit_logic

        elif "Sar" in bin_op:

            ir_category = IRCategory.bit_logic

        elif "Xor" in bin_op:

            ir_category = IRCategory.bit_logic

        elif re.compile(r".*Iop_[VIFS]?(\d*)[HS]?L?to[VIF]?(\d*)[S]?").match(bin_op) is not None:

            # e.g. 32HLto64 ; F64toF32
            p = re.compile(r".*Iop_[VIFS]?(\d*)[HS]?L?to[VIF]?(\d*)[S]?").match(bin_op)

            logger.debug("bin_op: '{}'".format(bin_op))

            operand_0 = int(p.group(1), 0)

            operand_1 = int(p.group(2), 0)

            if operand_0 < operand_1:

                ir_category = IRCategory.bit_extend

            elif operand_0 > operand_1:

                ir_category = IRCategory.bit_trunc

            else:
                # Case with equality (i.e. operand_0 == operand_1)
                ir_category = IRCategory.other

        else:
            logger.debug(
                "Unsupported binary operation '{}'. Defaulting IR category to IRCategory.other".format(bin_op))
            ir_category = IRCategory.other

        return ir_category

    @staticmethod
    def _get_ir_category_from_unop(unop_expr_data):

        # The ir category that this read temp expression falls under
        ir_category = None

        unary_op = unop_expr_data.op

        # # Handle the extend and truncate unary expressions
        # # e.g. "Iop_64HIto32", "Iop_I32StoF64"
        p = re.compile(r".*Iop_[VH]?[FI]?(\d*)[SUH]?[I]?to[FV]?(\d*)")
        m = p.match(unary_op)
        if m:

            first_group = m.group(1)
            second_group = m.group(2)

            # Check if the groups are not empty before converting to integers
            if first_group and second_group:
                first_int = int(first_group, 0)
                second_int = int(second_group, 0)

                if first_int < second_int:
                    ir_category = IRCategory.bit_extend
                else:
                    ir_category = IRCategory.bit_trunc
            else:
                # Handle the case where one or both groups are empty
                ir_category = IRCategory.other
                logger.debug("One of the matched groups is empty. Cannot convert to integers.")

        elif "Not" in unary_op:

            ir_category = IRCategory.bit_logic

        else:

            logger.debug("Unsupported unary operation '{}'. "
                         "Defaulting IR category to be IRCategory.other ".format(unary_op))

            ir_category = IRCategory.other

        return ir_category

    @property
    def category(self):
        return VexInstructionContext._get_ir_category_from_statement(self._instruction)

    @property
    def mnemonic(self):
        return VexInstructionContext._get_mnemonic_from_statement(self._instruction)
