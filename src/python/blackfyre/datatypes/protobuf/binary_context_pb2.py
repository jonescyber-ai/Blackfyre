# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: binary_context.proto
# Protobuf Python Version: 4.25.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import blackfyre.datatypes.protobuf.pe_header_pb2 as pe__header__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x14\x62inary_context.proto\x12\x12\x62lackfyre.protobuf\x1a\x0fpe_header.proto\"\x93\t\n\rBinaryContext\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x13\n\x0bsha256_hash\x18\x02 \x01(\t\x12\x11\n\tproc_type\x18\x03 \x01(\r\x12\x11\n\tfile_type\x18\x04 \x01(\r\x12\x11\n\tword_size\x18\x05 \x01(\r\x12\x0f\n\x07\x65ndness\x18\x06 \x01(\r\x12<\n\x12import_symbol_list\x18\x07 \x03(\x0b\x32 .blackfyre.protobuf.ImportSymbol\x12\x46\n\x0bstring_refs\x18\x08 \x03(\x0b\x32\x31.blackfyre.protobuf.BinaryContext.StringRefsEntry\x12\x13\n\x0blanguage_id\x18\t \x01(\t\x12\x17\n\x0ftotal_functions\x18\n \x01(\r\x12\x19\n\x11\x64isassembler_type\x18\x0b \x01(\r\x12X\n\x15\x63\x61llee_to_callers_map\x18\x0c \x03(\x0b\x32\x39.blackfyre.protobuf.BinaryContext.CalleeToCallersMapEntry\x12X\n\x15\x63\x61ller_to_callees_map\x18\r \x03(\x0b\x32\x39.blackfyre.protobuf.BinaryContext.CallerToCalleesMapEntry\x12\x31\n\tpe_header\x18\x0e \x01(\x0b\x32\x1c.blackfyre.protobuf.PEHeaderH\x00\x12O\n\x10\x64\x65\x66ined_data_map\x18\x0f \x03(\x0b\x32\x35.blackfyre.protobuf.BinaryContext.DefinedDataMapEntry\x12\x1a\n\x12total_instructions\x18\x10 \x01(\x04\x12\x1d\n\x11\x63ontainer_version\x18\x11 \x01(\x02\x42\x02\x18\x01\x12<\n\x12\x65xport_symbol_list\x18\x12 \x03(\x0b\x32 .blackfyre.protobuf.ExportSymbol\x12\x11\n\tfile_size\x18\x13 \x01(\x04\x12\x13\n\x0b\x62\x63\x63_version\x18\x14 \x01(\t\x12\x1c\n\x14\x64isassembler_version\x18\x15 \x01(\t\x1a\x31\n\x0fStringRefsEntry\x12\x0b\n\x03key\x18\x01 \x01(\x04\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\\\n\x17\x43\x61lleeToCallersMapEntry\x12\x0b\n\x03key\x18\x01 \x01(\x04\x12\x30\n\x05value\x18\x02 \x01(\x0b\x32!.blackfyre.protobuf.ListOfCallers:\x02\x38\x01\x1a\\\n\x17\x43\x61llerToCalleesMapEntry\x12\x0b\n\x03key\x18\x01 \x01(\x04\x12\x30\n\x05value\x18\x02 \x01(\x0b\x32!.blackfyre.protobuf.ListOfCallees:\x02\x38\x01\x1aV\n\x13\x44\x65\x66inedDataMapEntry\x12\x0b\n\x03key\x18\x01 \x01(\x04\x12.\n\x05value\x18\x02 \x01(\x0b\x32\x1f.blackfyre.protobuf.DefinedData:\x02\x38\x01\x42\x08\n\x06header\"J\n\x0cImportSymbol\x12\x13\n\x0bimport_name\x18\x01 \x01(\t\x12\x14\n\x0clibrary_name\x18\x02 \x01(\t\x12\x0f\n\x07\x61\x64\x64ress\x18\x03 \x01(\x04\" \n\rListOfCallers\x12\x0f\n\x07\x63\x61llers\x18\x01 \x03(\x04\" \n\rListOfCallees\x12\x0f\n\x07\x63\x61llees\x18\x01 \x03(\x04\"i\n\x0b\x44\x65\x66inedData\x12\x0f\n\x07\x61\x64\x64ress\x18\x01 \x01(\x04\x12\x12\n\ndata_bytes\x18\x02 \x01(\x0c\x12\x11\n\tdata_type\x18\x03 \x01(\r\x12\x12\n\nreferences\x18\x04 \x03(\x04\x12\x0e\n\x06length\x18\x05 \x01(\r\"J\n\x0c\x45xportSymbol\x12\x13\n\x0b\x65xport_name\x18\x01 \x01(\t\x12\x14\n\x0clibrary_name\x18\x02 \x01(\t\x12\x0f\n\x07\x61\x64\x64ress\x18\x03 \x01(\x04\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'binary_context_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR._options = None
  _globals['_BINARYCONTEXT_STRINGREFSENTRY']._options = None
  _globals['_BINARYCONTEXT_STRINGREFSENTRY']._serialized_options = b'8\001'
  _globals['_BINARYCONTEXT_CALLEETOCALLERSMAPENTRY']._options = None
  _globals['_BINARYCONTEXT_CALLEETOCALLERSMAPENTRY']._serialized_options = b'8\001'
  _globals['_BINARYCONTEXT_CALLERTOCALLEESMAPENTRY']._options = None
  _globals['_BINARYCONTEXT_CALLERTOCALLEESMAPENTRY']._serialized_options = b'8\001'
  _globals['_BINARYCONTEXT_DEFINEDDATAMAPENTRY']._options = None
  _globals['_BINARYCONTEXT_DEFINEDDATAMAPENTRY']._serialized_options = b'8\001'
  _globals['_BINARYCONTEXT'].fields_by_name['container_version']._options = None
  _globals['_BINARYCONTEXT'].fields_by_name['container_version']._serialized_options = b'\030\001'
  _globals['_BINARYCONTEXT']._serialized_start=62
  _globals['_BINARYCONTEXT']._serialized_end=1233
  _globals['_BINARYCONTEXT_STRINGREFSENTRY']._serialized_start=898
  _globals['_BINARYCONTEXT_STRINGREFSENTRY']._serialized_end=947
  _globals['_BINARYCONTEXT_CALLEETOCALLERSMAPENTRY']._serialized_start=949
  _globals['_BINARYCONTEXT_CALLEETOCALLERSMAPENTRY']._serialized_end=1041
  _globals['_BINARYCONTEXT_CALLERTOCALLEESMAPENTRY']._serialized_start=1043
  _globals['_BINARYCONTEXT_CALLERTOCALLEESMAPENTRY']._serialized_end=1135
  _globals['_BINARYCONTEXT_DEFINEDDATAMAPENTRY']._serialized_start=1137
  _globals['_BINARYCONTEXT_DEFINEDDATAMAPENTRY']._serialized_end=1223
  _globals['_IMPORTSYMBOL']._serialized_start=1235
  _globals['_IMPORTSYMBOL']._serialized_end=1309
  _globals['_LISTOFCALLERS']._serialized_start=1311
  _globals['_LISTOFCALLERS']._serialized_end=1343
  _globals['_LISTOFCALLEES']._serialized_start=1345
  _globals['_LISTOFCALLEES']._serialized_end=1377
  _globals['_DEFINEDDATA']._serialized_start=1379
  _globals['_DEFINEDDATA']._serialized_end=1484
  _globals['_EXPORTSYMBOL']._serialized_start=1486
  _globals['_EXPORTSYMBOL']._serialized_end=1560
# @@protoc_insertion_point(module_scope)