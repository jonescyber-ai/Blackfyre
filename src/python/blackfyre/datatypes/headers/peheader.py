import os

from blackfyre.util import setup_custom_logger
from blackfyre.datatypes.headers.header import Header

logger = setup_custom_logger(os.path.splitext(os.path.basename(__file__))[0])


class PEHeader(Header):
    __slots__ = ['_time_stamp', '_size_of_image', '_address_of_entry_point', '_size_of_initialized_data',
                 '_size_of_code', '_size_of_raw_data', '_checksum', '_dll_characteristics', '_number_of_sections',
                 '_major_linker_version', '_major_image_version', '_size_of_uninitialized_data', '_base_of_code',
                 '_minor_linker_version', '_size_of_headers', '_major_operating_system_version',
                 '_size_of_stack_reserve',
                 '_file_alignment', '_minor_image_version', '_major_subsystem_version', '_size_of_stack_commit',
                 '_size_of_heap_reserve', '_nt_header_name']

    def __init__(self, time_stamp, size_of_image, address_of_entry_point, size_of_initialized_data,
                 size_of_code, size_of_raw_data, checksum, dll_characteristics, number_of_sections,
                 major_linker_version, major_image_version, size_of_uninitialized_data, base_of_code,
                 minor_linker_version, size_of_headers, major_operating_system_version, size_of_stack_reserve,
                 file_alignment, minor_image_version, major_subsystem_version, size_of_stack_commit,
                 size_of_heap_reserve, nt_header_name):
        self._time_stamp = time_stamp

        self._size_of_image = size_of_image

        self._address_of_entry_point = address_of_entry_point

        self._size_of_initialized_data = size_of_initialized_data

        self._size_of_code = size_of_code

        self._size_of_raw_data = size_of_raw_data

        self._checksum = checksum

        self._dll_characteristics = dll_characteristics

        self._number_of_sections = number_of_sections

        self._major_linker_version = major_linker_version

        self._major_image_version = major_image_version

        self._size_of_uninitialized_data = size_of_uninitialized_data

        self._base_of_code = base_of_code

        self._minor_linker_version = minor_linker_version

        self._size_of_headers = size_of_headers

        self._major_operating_system_version = major_operating_system_version

        self._size_of_stack_reserve = size_of_stack_reserve

        self._file_alignment = file_alignment

        self._minor_image_version = minor_image_version

        self._major_subsystem_version = major_subsystem_version

        self._size_of_stack_commit = size_of_stack_commit

        self._size_of_heap_reserve = size_of_heap_reserve

        self._nt_header_name = nt_header_name

        super().__init__()




    @classmethod
    def from_pb(cls, pe_header_pb):

        time_stamp = pe_header_pb.time_stamp

        size_of_image = pe_header_pb.size_of_image

        address_of_entry_point = pe_header_pb.address_of_entry_point

        size_of_initialized_data = pe_header_pb.size_of_initialized_data

        size_of_code = pe_header_pb.size_of_code

        size_of_raw_data = pe_header_pb.size_of_raw_data

        checksum = pe_header_pb.checksum

        dll_characteristics = pe_header_pb.dll_characteristics

        number_of_sections = pe_header_pb.number_of_sections

        major_linker_version = pe_header_pb.major_linker_version

        major_image_version = pe_header_pb.major_image_version

        size_of_uninitialized_data = pe_header_pb.size_of_uninitialized_data

        base_of_code = pe_header_pb.base_of_code

        minor_linker_version = pe_header_pb.minor_linker_version

        size_of_headers = pe_header_pb.size_of_headers

        major_operating_system_version = pe_header_pb.major_operating_system_version

        size_of_stack_reserve = pe_header_pb.size_of_stack_reserve

        file_alignment = pe_header_pb.file_alignment

        minor_image_version = pe_header_pb.minor_image_version

        major_subsystem_version = pe_header_pb.major_subsystem_version

        size_of_stack_commit = pe_header_pb.size_of_stack_commit

        size_of_heap_reserve = pe_header_pb.size_of_heap_reserve

        nt_header_name = pe_header_pb.nt_header_name

        pe_header = cls(time_stamp, size_of_image, address_of_entry_point, size_of_initialized_data,
                        size_of_code, size_of_raw_data, checksum, dll_characteristics, number_of_sections,
                        major_linker_version, major_image_version, size_of_uninitialized_data, base_of_code,
                        minor_linker_version, size_of_headers, major_operating_system_version, size_of_stack_reserve,
                        file_alignment, minor_image_version, major_subsystem_version, size_of_stack_commit,
                        size_of_heap_reserve, nt_header_name)

        return pe_header

    @property
    def time_stamp(self):
        return self._time_stamp

    @property
    def size_of_image(self):
        return self._size_of_image

    @property
    def address_of_entry_point(self):
        return self._address_of_entry_point

    @property
    def size_of_initialized_data(self):
        return self._size_of_initialized_data

    @property
    def size_of_code(self):
        return self._size_of_code

    @property
    def size_of_raw_data(self):
        return self._size_of_raw_data

    @property
    def checksum(self):
        return self._checksum

    @property
    def dll_characteristics(self):
        return self._dll_characteristics

    @property
    def number_of_sections(self):
        return self._number_of_sections

    @property
    def major_linker_version(self):
        return self._major_linker_version

    @property
    def major_image_version(self):
        return self._major_image_version

    @property
    def size_of_uninitialized_data(self):
        return self._size_of_uninitialized_data

    @property
    def base_of_code(self):
        return self._base_of_code

    @property
    def minor_linker_version(self):
        return self._minor_linker_version

    @property
    def size_of_headers(self):
        return self._size_of_headers

    @property
    def major_operating_system_version(self):
        return self._major_operating_system_version

    @property
    def size_of_stack_reserve(self):
        return self._size_of_stack_reserve

    @property
    def file_alignment(self):
        return self._file_alignment

    @property
    def minor_image_version(self):
        return self._minor_image_version

    @property
    def major_subsystem_version(self):
        return self._major_subsystem_version

    @property
    def size_of_stack_commit(self):
        return self._size_of_stack_commit

    @property
    def size_of_heap_reserve(self):
        return self._size_of_heap_reserve

    @property
    def nt_header_name(self):
        return self._nt_header_name




