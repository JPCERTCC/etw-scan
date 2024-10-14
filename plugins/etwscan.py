# ETW Scanner: Volatility3 Plugin to detect ETW Providers and Consumers in Windows memory
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/etw-scan/
#

import logging
from typing import Iterable, Tuple

from volatility3.framework import (constants, exceptions, interfaces, layers, renderers, symbols)
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import handles, pslist, vadinfo

vollog = logging.getLogger(__name__)

try:
    import capstone
    has_capstone = True
except ImportError:
    has_capstone = False

# Sample headers to add to an ETL file
ETL_HEADER = b"\x00\x00\x01\x00\x20\x02\x00\x00\x20\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x03\x00\x00\x00\x20\x02\x00\x00\x21\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x02\xC0\x82\x01\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xCF\x8A\xAC\x20\x05\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x0A\x00\x01\x05\x00\x00\x00\x00\x01\x00\x00\x00\x00\xC0\x89\x76\x45\x3C\xDA\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE4\xFD\xFF\xFF\x40\x00\x74\x00\x7A\x00\x72\x00\x65\x00\x73\x00\x2E\x00\x64\x00\x6C\x00\x6C\x00\x2C\x00\x2D\x00\x32\x00\x36\x00\x32\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x74\x00\x7A\x00\x00\x32\x64\x00\x73\x00\x2E\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2D\x00\x36\x00\x33\x00\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xC4\xFF\xFF\xFF\x00\x00\x00\x00\x40\x5E\x16\xA1\xC5\xDF\xDA\x01\x80\x96\x98\x00\x00\x00\x00\x00\xB0\xF3\x52\xC1\xCA\xDF\xDA\x01\x01\x00\x00\x00\x00\x00\x00\x00\x74\x00\x65\x00\x73\x00\x74\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x02\xC0\x50\x00\x50\x00\xCC\x1B\x00\x00\x10\x36\x00\x00\xCF\x8A\xAC\x20\x05\x00\x00\x00\xCE\x00\x00\x00\x5D\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


class etwProvider(interfaces.plugins.PluginInterface):
    """Detect ETW Providers in Windows memory"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name='primary',
                                                     description='Memory layer for the kernel',
                                                     architectures=["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name="nt_symbols",
                                                description="Windows kernel symbols"),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.PluginRequirement(name='vadinfo',
                                           plugin=vadinfo.VadInfo,
                                           version=(2, 0, 0)),
            requirements.PluginRequirement(name="handles",
                                           plugin=handles.Handles,
                                           version=(1, 0, 0)),
            requirements.ListRequirement(name='pid',
                                         description='Filter on specific process IDs',
                                         element_type=int,
                                         optional=True),
            requirements.BooleanRequirement(
                name="all",
                description="List all ETW Providers (with Disable providers)",
                default=False,
                optional=True,
            ),
        ]

    @staticmethod
    def get_vad_maps(task: interfaces.objects.ObjectInterface) -> Iterable[Tuple[int, int]]:
        """Creates a map of start/end addresses within a virtual address
        descriptor tree.
        Args:
            task: The EPROCESS object of which to traverse the vad tree
        Returns:
            An iterable of tuples containing start and end addresses for each descriptor
        """
        vad_root = task.get_vad_root()
        for vad in vad_root.traverse():
            end = vad.get_end()
            start = vad.get_start()
            yield (start, end - start)

    @staticmethod
    def get_vad_base(task: interfaces.objects.ObjectInterface,
                     address: int) -> interfaces.objects.ObjectInterface:
        """Get the VAD address block which contains the second argument address."""
        for vad in task.get_vad_root().traverse():
            end = vad.get_end()
            start = vad.get_start()
            if start <= address and address <= end:
                return vad

    def _decode_pointer(self, value, magic):
        """Windows encodes pointers to objects and decodes them on the fly
        before using them.

        This function mimics the decoding routine so we can generate the
        proper pointer values as well.
        """

        value = value & 0xFFFFFFFFFFFFFFF8
        value = value >> magic
        # if (value & (1 << 47)):
        #    value = value | 0xFFFF000000000000

        return value

    def _find_sar_value(self, context, layer_name, symbol_table_name):
        """Locate ObpCaptureHandleInformationEx if it exists in the sample.

        Once found, parse it for the SAR value that we need to decode
        pointers in the _HANDLE_TABLE_ENTRY which allows us to find the
        associated _OBJECT_HEADER.
        """

        if not has_capstone:
            return None

        virtual_layer_name = layer_name
        kvo = context.layers[virtual_layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table_name, layer_name=virtual_layer_name, offset=kvo)

        try:
            func_addr = ntkrnlmp.get_symbol("ObpCaptureHandleInformationEx").address
        except exceptions.SymbolError:
            return None

        data = context.layers.read(virtual_layer_name, kvo + func_addr, 0x200)
        if data is None:
            return None

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

        for _, _, mnemonic, op_str in md.disasm_lite(data, kvo + func_addr):

            if mnemonic.startswith("sar"):
                # if we don't want to parse op strings, we can disasm the
                # single sar instruction again, but we use disasm_lite for speed
                _sar_value = int(op_str.split(",")[1].strip(), 16)
                break

        return _sar_value

    def _get_item(self, handle_table_entry, handle_value, context, layer_name, symbol_table_name):
        """Given  a handle table entry (_HANDLE_TABLE_ENTRY) structure from a
        process' handle table, determine where the corresponding object's
        _OBJECT_HEADER can be found."""

        virtual = layer_name

        try:
            # before windows 7
            if not context.layers[virtual].is_valid(handle_table_entry.Object):
                return None
            fast_ref = handle_table_entry.Object.cast("_EX_FAST_REF")
            object_header = fast_ref.dereference().cast("_OBJECT_HEADER")
            object_header.GrantedAccess = handle_table_entry.GrantedAccess
        except AttributeError:
            # starting with windows 8
            is_64bit = symbols.symbol_table_is_64bit(context, symbol_table_name)

            if is_64bit:
                if handle_table_entry.LowValue == 0:
                    return None

                magic = self._find_sar_value(context, layer_name, symbol_table_name)

                # is this the right thing to raise here?
                if magic is None:
                    if has_capstone:
                        raise AttributeError(
                            "Unable to find the SAR value for decoding handle table pointers")
                    else:
                        raise exceptions.MissingModuleException(
                            "capstone",
                            "Requires capstone to find the SAR value for decoding handle table pointers",
                        )

                offset = self._decode_pointer(handle_table_entry.LowValue, magic)
            else:
                if handle_table_entry.InfoTable == 0:
                    return None

                offset = handle_table_entry.InfoTable & ~7

            object_header = context.object(
                symbol_table_name + constants.BANG + "_OBJECT_HEADER",
                virtual,
                offset=offset,
            )
            object_header.GrantedAccess = handle_table_entry.GrantedAccessBits

        object_header.HandleValue = handle_value
        return object_header

    def _make_handle_array(self, offset, level, context, layer_name, symbol_table_name, depth=0):
        """Parse a process' handle table and yield valid handle table entries,
        going as deep into the table "levels" as necessary."""

        virtual = layer_name
        kvo = context.layers[virtual].config["kernel_virtual_offset"]

        ntkrnlmp = context.module(symbol_table_name, layer_name=virtual, offset=kvo)

        if level > 0:
            subtype = ntkrnlmp.get_type("pointer")
            count = 0x1000 / subtype.size
        else:
            subtype = ntkrnlmp.get_type("_HANDLE_TABLE_ENTRY")
            count = 0x1000 / subtype.size

        if not context.layers[virtual].is_valid(offset):
            return None

        table = ntkrnlmp.object(
            object_type="array",
            offset=offset,
            subtype=subtype,
            count=int(count),
            absolute=True,
        )

        layer_object = context.layers[virtual]
        masked_offset = offset & layer_object.maximum_address

        for entry in table:
            if level > 0:
                for x in self._make_handle_array(entry, level - 1, context, layer_name,
                                                 symbol_table_name, depth):
                    yield x
                depth += 1
            else:
                handle_multiplier = 4
                handle_level_base = depth * count * handle_multiplier

                handle_value = ((entry.vol.offset - masked_offset) /
                                (subtype.size / handle_multiplier)) + handle_level_base

                item = self._get_item(entry, handle_value, context, layer_name, symbol_table_name)

                if item is None:
                    continue

                try:
                    if item.TypeIndex != 0x0:
                        yield item
                except AttributeError:
                    if item.Type.Name:
                        yield item
                except exceptions.InvalidAddressException:
                    continue

    def _handles(self, handle_table, context, layer_name, symbol_table_name):
        level_mask = 7
        try:
            TableCode = handle_table.TableCode & ~level_mask
            table_levels = handle_table.TableCode & level_mask
        except exceptions.InvalidAddressException:
            vollog.log(
                constants.LOGLEVEL_VVV,
                "Handle table parsing was aborted due to an invalid address exception",
            )
            return None

        for handle_table_entry in self._make_handle_array(TableCode, table_levels, context,
                                                          layer_name, symbol_table_name):
            yield handle_table_entry

    def _generator(self, tasks):
        """Generate ETW registration context information for each task.
        
        Args:
            tasks: The list of task objects (processes) to inspect.
        
        Yields:
            Tuple containing information about each ETW registration.
        """
        for task in tasks:
            layer_name = task.add_process_layer()
            symbol_table = self.config['nt_symbols']

            # Get the object type map and cookie for handle resolution
            try:
                type_map = handles.Handles.get_type_map(context=self.context,
                                                        layer_name=layer_name,
                                                        symbol_table=symbol_table)
                cookie = handles.Handles.find_cookie(context=self.context,
                                                     layer_name=layer_name,
                                                     symbol_table=symbol_table)
            except:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    "Cannot get type map or cookie",
                )
                continue

            try:
                object_table = task.ObjectTable
            except exceptions.InvalidAddressException:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    f"Cannot access _EPROCESS.ObjectType at {task.vol.offset:#x}",
                )
                continue

            # Iterate through each handle in the object table
            for entry in self._handles(object_table, self.context, layer_name, symbol_table):
                try:
                    obj_type = entry.get_object_type(type_map, cookie)
                    if obj_type is None:
                        continue

                    # Check if the object type is EtwRegistration
                    if obj_type == "EtwRegistration":
                        item = entry.Body.cast("_ETW_REG_ENTRY")

                        enable_mask = item.get_provider_enablemask()
                        provider_guid = item.get_guid()
                        logger_id = item.get_provider_loggerid()
                        logger_level = item.get_provider_level() or "No"

                        # Check if the provider is enabled
                        if item.isenable_provider():

                            # Yield information about the ETW registration
                            yield (0,
                                   (task.UniqueProcessId,
                                    task.ImageFileName.cast("string",
                                                            max_length=task.ImageFileName.vol.count,
                                                            errors='replace'), obj_type,
                                    format_hints.Hex(entry.Body.vol.offset), provider_guid,
                                    logger_id, logger_level, enable_mask))
                        elif self.config["all"]:

                            # Yield information about the ETW registration
                            yield (0,
                                   (task.UniqueProcessId,
                                    task.ImageFileName.cast("string",
                                                            max_length=task.ImageFileName.vol.count,
                                                            errors='replace'), obj_type,
                                    format_hints.Hex(entry.Body.vol.offset), provider_guid,
                                    logger_id, logger_level, enable_mask))

                except exceptions.InvalidAddressException:
                    vollog.log(
                        constants.LOGLEVEL_VVV,
                        f"Cannot access _OBJECT_HEADER at {entry.vol.offset:#x}",
                    )
                    continue

    def run(self) -> renderers.TreeGrid:
        layer = self.context.layers[self.config['primary']]
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        # Ensure the layer is compatible with Windows OS
        if layer.metadata.get('os', None) in ['Windows', 'Unknown']:
            return renderers.TreeGrid([("PID", int), ("ImageFileName", str), ("TypeMap", str),
                                       ("Address", format_hints.Hex), ("Guid", str),
                                       ("LoggerId", int), ("Level", str), ("EnableMask", str)],
                                      self._generator(
                                          pslist.PsList.list_processes(
                                              context=self.context,
                                              layer_name=self.config['primary'],
                                              symbol_table=self.config['nt_symbols'],
                                              filter_func=filter_func)))
        else:
            vollog.error("This command does not support the selected profile.")


class etwConsumer(interfaces.plugins.PluginInterface):
    """Detect ETW Consumers and dump etl in Windows memory"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name='primary',
                                                     description='Memory layer for the kernel',
                                                     architectures=["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name="nt_symbols",
                                                description="Windows kernel symbols"),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.PluginRequirement(name='vadinfo',
                                           plugin=vadinfo.VadInfo,
                                           version=(2, 0, 0)),
            requirements.PluginRequirement(name="handles",
                                           plugin=handles.Handles,
                                           version=(1, 0, 0)),
            requirements.ListRequirement(name='pid',
                                         description='Filter on specific process IDs',
                                         element_type=int,
                                         optional=True),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract etl file in buffer",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="alldump",
                description="Extract etl file in all ETW structure",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="noheader",
                description="Extract etl file without TRACE_LOGFILE_HEADER (only ETW events)",
                default=False,
                optional=True,
            ),
        ]

    @staticmethod
    def get_vad_maps(task: interfaces.objects.ObjectInterface) -> Iterable[Tuple[int, int]]:
        """Creates a map of start/end addresses within a virtual address
        descriptor tree.
        Args:
            task: The EPROCESS object of which to traverse the vad tree
        Returns:
            An iterable of tuples containing start and end addresses for each descriptor
        """
        vad_root = task.get_vad_root()
        for vad in vad_root.traverse():
            end = vad.get_end()
            start = vad.get_start()
            yield (start, end - start)

    @staticmethod
    def get_vad_base(task: interfaces.objects.ObjectInterface,
                     address: int) -> interfaces.objects.ObjectInterface:
        """Get the VAD address block which contains the second argument address."""
        for vad in task.get_vad_root().traverse():
            end = vad.get_end()
            start = vad.get_start()
            if start <= address and address <= end:
                return vad

    @classmethod
    def get_version_structure(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> interfaces.objects.ObjectInterface:
        """Returns the KdVersionBlock information from a kernel"""
        ntkrnlmp = cls.get_kernel_module(context, layer_name, symbol_table)

        vers_offset = ntkrnlmp.get_symbol("KdVersionBlock").address

        vers = ntkrnlmp.object(
            object_type="_DBGKD_GET_VERSION64",
            layer_name=layer_name,
            offset=vers_offset,
        )

        return vers

    @classmethod
    def get_kernel_module(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ):
        """Returns the kernel module based on the layer and symbol_table"""
        virtual_layer = context.layers[layer_name]
        if not isinstance(virtual_layer, layers.intel.Intel):
            raise TypeError("Virtual Layer is not an intel layer")

        kvo = virtual_layer.config["kernel_virtual_offset"]

        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)
        return ntkrnlmp

    def _decode_pointer(self, value, magic):
        """Windows encodes pointers to objects and decodes them on the fly
        before using them.

        This function mimics the decoding routine so we can generate the
        proper pointer values as well.
        """

        value = value & 0xFFFFFFFFFFFFFFF8
        value = value >> magic
        # if (value & (1 << 47)):
        #    value = value | 0xFFFF000000000000

        return value

    def _find_sar_value(self, context, layer_name, symbol_table_name):
        """Locate ObpCaptureHandleInformationEx if it exists in the sample.

        Once found, parse it for the SAR value that we need to decode
        pointers in the _HANDLE_TABLE_ENTRY which allows us to find the
        associated _OBJECT_HEADER.
        """

        if not has_capstone:
            return None

        virtual_layer_name = layer_name
        kvo = context.layers[virtual_layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table_name, layer_name=virtual_layer_name, offset=kvo)

        try:
            func_addr = ntkrnlmp.get_symbol("ObpCaptureHandleInformationEx").address
        except exceptions.SymbolError:
            return None

        data = context.layers.read(virtual_layer_name, kvo + func_addr, 0x200)
        if data is None:
            return None

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

        for _, _, mnemonic, op_str in md.disasm_lite(data, kvo + func_addr):

            if mnemonic.startswith("sar"):
                # if we don't want to parse op strings, we can disasm the
                # single sar instruction again, but we use disasm_lite for speed
                _sar_value = int(op_str.split(",")[1].strip(), 16)
                break

        return _sar_value

    def _get_item(self, handle_table_entry, handle_value, context, layer_name, symbol_table_name):
        """Given  a handle table entry (_HANDLE_TABLE_ENTRY) structure from a
        process' handle table, determine where the corresponding object's
        _OBJECT_HEADER can be found."""

        virtual = layer_name

        try:
            # before windows 7
            if not context.layers[virtual].is_valid(handle_table_entry.Object):
                return None
            fast_ref = handle_table_entry.Object.cast("_EX_FAST_REF")
            object_header = fast_ref.dereference().cast("_OBJECT_HEADER")
            object_header.GrantedAccess = handle_table_entry.GrantedAccess
        except AttributeError:
            # starting with windows 8
            is_64bit = symbols.symbol_table_is_64bit(context, symbol_table_name)

            if is_64bit:
                try:
                    if handle_table_entry.LowValue == 0:
                        return None
                except:
                    vollog.log(
                        constants.LOGLEVEL_VVV,
                        "Can't get _HANDLE_TABLE_ENTRY LowValue",
                    )
                    return None

                magic = self._find_sar_value(context, layer_name, symbol_table_name)

                # is this the right thing to raise here?
                if magic is None:
                    if has_capstone:
                        raise AttributeError(
                            "Unable to find the SAR value for decoding handle table pointers")
                    else:
                        raise exceptions.MissingModuleException(
                            "capstone",
                            "Requires capstone to find the SAR value for decoding handle table pointers",
                        )

                offset = self._decode_pointer(handle_table_entry.LowValue, magic)
            else:
                if handle_table_entry.InfoTable == 0:
                    return None

                offset = handle_table_entry.InfoTable & ~7

            object_header = context.object(
                symbol_table_name + constants.BANG + "_OBJECT_HEADER",
                virtual,
                offset=offset,
            )
            object_header.GrantedAccess = handle_table_entry.GrantedAccessBits

        object_header.HandleValue = handle_value
        return object_header

    def _make_handle_array(self, offset, level, context, layer_name, symbol_table_name, depth=0):
        """Parse a process' handle table and yield valid handle table entries,
        going as deep into the table "levels" as necessary."""

        virtual = layer_name
        kvo = context.layers[virtual].config["kernel_virtual_offset"]

        ntkrnlmp = context.module(symbol_table_name, layer_name=virtual, offset=kvo)

        if level > 0:
            subtype = ntkrnlmp.get_type("pointer")
            count = 0x1000 / subtype.size
        else:
            subtype = ntkrnlmp.get_type("_HANDLE_TABLE_ENTRY")
            count = 0x1000 / subtype.size

        if not context.layers[virtual].is_valid(offset):
            return None

        table = ntkrnlmp.object(
            object_type="array",
            offset=offset,
            subtype=subtype,
            count=int(count),
            absolute=True,
        )

        layer_object = context.layers[virtual]
        masked_offset = offset & layer_object.maximum_address

        for entry in table:
            if level > 0:
                for x in self._make_handle_array(entry, level - 1, context, layer_name,
                                                 symbol_table_name, depth):
                    yield x
                depth += 1
            else:
                handle_multiplier = 4
                handle_level_base = depth * count * handle_multiplier

                handle_value = ((entry.vol.offset - masked_offset) /
                                (subtype.size / handle_multiplier)) + handle_level_base

                item = self._get_item(entry, handle_value, context, layer_name, symbol_table_name)

                if item is None:
                    continue

                try:
                    if item.TypeIndex != 0x0:
                        yield item
                except AttributeError:
                    if item.Type.Name:
                        yield item
                except exceptions.InvalidAddressException:
                    continue

    def _handles(self, handle_table, context, layer_name, symbol_table_name):
        level_mask = 7
        try:
            TableCode = handle_table.TableCode & ~level_mask
            table_levels = handle_table.TableCode & level_mask
        except exceptions.InvalidAddressException:
            vollog.log(
                constants.LOGLEVEL_VVV,
                "Handle table parsing was aborted due to an invalid address exception",
            )
            return None

        for handle_table_entry in self._make_handle_array(TableCode, table_levels, context,
                                                          layer_name, symbol_table_name):
            yield handle_table_entry

    def _dump_etl_from_globallist(self, logger_context, logger_name, layer, layer_name, ntkrnlmp):
        """Dump ETL file from ETW logger context GlobalList.
        
        Args:
            logger_context: The context of the logger.
            logger_name: The name of the logger.
            layer: The memory layer to read from.
            layer_name: The name of the memory layer.
            ntkrnlmp: The NT kernel module.
        """
        num_buffers = logger_context.get_number_of_buffers()
        list_entry = ntkrnlmp.object(object_type="_LIST_ENTRY",
                                     offset=logger_context.GlobalList.vol.offset,
                                     absolute=True)
        flink_list = self._get_flink_list(list_entry, num_buffers, logger_context)

        reloff = ntkrnlmp.get_type("_WMI_BUFFER_HEADER").relative_child_offset("GlobalEntry")

        # Iterate through the collected Flink pointers and write the buffer data to ETL files
        for flink in flink_list:
            event_data_offset = flink.Flink.vol.offset - reloff
            file_handle = self.open(
                f"{logger_name.replace(' ', '_')}.0x{event_data_offset:X}.global.etl")
            wmi_buffer = ntkrnlmp.object(object_type="_WMI_BUFFER_HEADER",
                                         offset=event_data_offset,
                                         absolute=True)

            self._write_buffer_to_file(file_handle, layer, event_data_offset, wmi_buffer.BufferSize,
                                       layer_name, logger_context)

    def _dump_etl_from_bufferqueue(self, logger_context, logger_name, layer, layer_name, ntkrnlmp):
        """Dump ETL file from ETW logger context BufferQueue.
        
        Args:
            logger_context: The context of the logger.
            logger_name: The name of the logger.
            layer: The memory layer to read from.
            layer_name: The name of the memory layer.
            ntkrnlmp: The NT kernel module.
        """
        try:
            list_entry = ntkrnlmp.object(object_type="_SINGLE_LIST_ENTRY",
                                         offset=logger_context.BufferQueue.QueueEntry.vol.offset,
                                         absolute=True)
            flink_list = self._get_flink_list_bufferqueue(list_entry,
                                                          logger_context.get_buffers_written(),
                                                          logger_context)
            reloff = ntkrnlmp.get_type("_WMI_BUFFER_HEADER").relative_child_offset("SlistEntry")

            for flink in flink_list:
                event_data_offset = flink.Next.vol.offset - reloff
                file_handle = self.open(
                    f"{logger_name.replace(' ', '_')}.0x{event_data_offset:X}.buffer.etl")
                wmi_buffer = ntkrnlmp.object(object_type="_WMI_BUFFER_HEADER",
                                             offset=event_data_offset,
                                             absolute=True)

                self._write_buffer_to_file(file_handle, layer, event_data_offset,
                                           wmi_buffer.BufferSize, layer_name, logger_context)
        except exceptions.InvalidAddressException:
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"Cannot access _SINGLE_LIST_ENTRY at {logger_context.BufferQueue.QueueEntry.vol.offset:#x}"
            )

    def _dump_etl_from_overflowqueue(self, logger_context, logger_name, layer, layer_name,
                                     ntkrnlmp):
        """Dump ETL file from ETW logger context OverflowQueue.
        
        Args:
            logger_context: The context of the logger.
            logger_name: The name of the logger.
            layer: The memory layer to read from.
            layer_name: The name of the memory layer.
            ntkrnlmp: The NT kernel module.
        """
        try:
            list_entry = ntkrnlmp.object(object_type="_SINGLE_LIST_ENTRY",
                                         offset=logger_context.OverflowQueue.QueueEntry.vol.offset,
                                         absolute=True)
            flink_list = self._get_flink_list_bufferqueue(list_entry,
                                                          logger_context.get_buffers_written(),
                                                          logger_context)
            reloff = ntkrnlmp.get_type("_WMI_BUFFER_HEADER").relative_child_offset("SlistEntry")

            for flink in flink_list:
                event_data_offset = flink.Next.vol.offset - reloff
                file_handle = self.open(
                    f"{logger_name.replace(' ', '_')}.0x{event_data_offset:X}.overflow.etl")
                wmi_buffer = ntkrnlmp.object(object_type="_WMI_BUFFER_HEADER",
                                             offset=event_data_offset,
                                             absolute=True)

                self._write_buffer_to_file(file_handle, layer, event_data_offset,
                                           wmi_buffer.BufferSize, layer_name, logger_context)
        except exceptions.InvalidAddressException:
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"Cannot access _SINGLE_LIST_ENTRY at {logger_context.OverflowQueue.QueueEntry.vol.offset:#x}"
            )

    def _dump_etl_from_userbufferlist(self, logger_context, consumer, logger_name, layer,
                                      layer_name, ntkrnlmp):
        """Dump ETL file from ETW logger context UserBufferList.
        
        Args:
            logger_context: The context of the logger.
            consumer: The context of the TransitionConsumer.
            logger_name: The name of the logger.
            layer: The memory layer to read from.
            layer_name: The name of the memory layer.
            ntkrnlmp: The NT kernel module.
        """
        list_entry = ntkrnlmp.object(object_type="_SINGLE_LIST_ENTRY",
                                     offset=consumer.UserBufferListHead.vol.offset,
                                     absolute=True)
        flink_list = []
        for _ in range(consumer.UserBufferCount):
            list_entry = list_entry.Next
            if list_entry == 0:
                break
            flink_list.append(list_entry)

        for flink in flink_list:
            buffer_offset = flink.Next.vol.offset
            event_data_offset = int.from_bytes(layer.read(buffer_offset + 0x28, 8, pad=True),
                                               'little')
            file_handle = self.open(
                f"{logger_name.replace(' ', '_')}.0x{event_data_offset:X}.realtime.etl")
            wmi_buffer = ntkrnlmp.object(object_type="_WMI_BUFFER_HEADER",
                                         offset=event_data_offset,
                                         absolute=True)
            self._write_buffer_to_file(file_handle, layer, event_data_offset, wmi_buffer.BufferSize,
                                       layer_name, logger_context)

    def _dump_etl_from_offset(self, logger_context, logger_name, layer, layer_name, ntkrnlmp,
                              event_data_offset, dataname):
        """Dump ETL file from ETW logger context with specific offset.
        
        Args:
            logger_context: The context of the logger.
            logger_name: The name of the logger.
            layer: The memory layer to read from.
            layer_name: The name of the memory layer.
            ntkrnlmp: The NT kernel module.
            event_data_offset: The offset of the event data in the memory layer.
            dataname: stracture value name (batch, compression etc).
        """
        wmi_buffer = ntkrnlmp.object(object_type="_WMI_BUFFER_HEADER",
                                     offset=event_data_offset - 0xf,
                                     absolute=True)
        file_handle = self.open(
            f"{logger_name.replace(' ', '_')}.0x{event_data_offset - 0xf:X}.{dataname}.etl")

        self._write_buffer_to_file(file_handle, layer, event_data_offset - 0xf,
                                   wmi_buffer.BufferSize, layer_name, logger_context)

    def _get_flink_list(self, list_entry, num_buffers, logger_context):
        """Retrieve the list of Flink pointers from the GlobalList.
        
        Args:
            list_entry: The initial list entry.
            num_buffers: The number of buffers to read.
            logger_context: The context of the logger.
        
        Returns:
            List of Flink pointers.
        """
        flink_list = []
        for _ in range(num_buffers):
            list_entry = list_entry.Flink
            if list_entry.Flink.vol.offset == logger_context.GlobalList.Flink.vol.offset:
                break
            flink_list.append(list_entry)
        return flink_list

    def _get_flink_list_bufferqueue(self, list_entry, num_buffers, logger_context):
        """Retrieve the list of Flink pointers from the BufferQueue.
        
        Args:
            list_entry: The initial list entry.
            num_buffers: The number of buffers to read.
            logger_context: The context of the logger.
        
        Returns:
            List of Flink pointers.
        """
        flink_list = []
        for _ in range(num_buffers):
            list_entry = list_entry.Next
            if list_entry.Next.vol.offset == logger_context.BufferQueue.QueueTail.Next.vol.offset or list_entry == 0:
                break
            flink_list.append(list_entry)
        return flink_list

    def _write_buffer_to_file(self, file_handle, layer, event_data_offset, size, layer_name,
                              logger_context):
        """Write buffer data to a file.
        
        Args:
            file_handle: The handle to the file to write to.
            layer: The memory layer to read from.
            event_data_offset: The offset of the event data in the memory layer.
            size: file size.
            layer_name: The name of the memory layer.
            logger_context: The context of the logger.
        """
        with file_handle as file_data:
            try:
                data = layer.read(event_data_offset, size, pad=True)
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Unable to write {layer_name}'s address {event_data_offset} to {file_handle.preferred_filename}"
                )

            # Default ETW events cannot be parsed because _TRACE_LOGFILE_HEADER is missing.
            # Therefore, a sample _TRACE_LOGFILE_HEADER is added.
            if self.config["noheader"]:
                file_data.write(data)
            else:
                time_lo = logger_context.StartTime.LowPart.to_bytes(4, 'little')
                time_hi = logger_context.StartTime.HighPart.to_bytes(4, 'little')
                start_time = time_lo + time_hi

                add_header = bytearray(ETL_HEADER)
                buffer_size = data[0:4]
                add_header[0:4] = buffer_size
                add_header[0x68:0x6c] = buffer_size
                add_header[0x78:0x80] = start_time
                add_header[0x160:0x168] = start_time
                add_header[0x170:0x178] = start_time
                add_header = add_header + (b"\xFF" * (size - 0x220))

                file_data.write(add_header + data)

    def _generate_etw_logger_context(self, vers, serversilo_globals_entry, ntkrnlmp):
        """Generate ETW logger context based on Windows version.
        
        Args:
            vers: The version structure of the Windows OS.
            serversilo_globals_entry: The server silo globals entry object.
            ntkrnlmp: The NT kernel module.
        
        Returns:
            List of ETW logger context objects.
        """
        # if Windows version is 10.0.16299 or higher, use EtwpLoggerContext
        # otherwise, use WmipLoggerContext
        if vers.MinorVersion >= 16299:
            EtwpLoggerContext_table_offset = serversilo_globals_entry.EtwSiloState.EtwpLoggerContext
            max_loggers = serversilo_globals_entry.EtwSiloState.MaxLoggers
            EtwpLoggerContext_table_ptr = ntkrnlmp.object(object_type="array",
                                                          offset=EtwpLoggerContext_table_offset,
                                                          subtype=ntkrnlmp.get_type("pointer"),
                                                          count=max_loggers,
                                                          absolute=True)
        else:
            EtwpLoggerContext_table_ptr = serversilo_globals_entry.EtwSiloState.WmipLoggerContext

        # Create a list of ETW logger context objects
        return [
            ntkrnlmp.object(object_type="_WMI_LOGGER_CONTEXT",
                            offset=EtwpLoggerContext_offset,
                            absolute=True)
            for EtwpLoggerContext_offset in EtwpLoggerContext_table_ptr
        ]

    def _generator(self, tasks):
        """Generate ETW logger context information for each task.
        
        Args:
            tasks: The list of task objects (processes) to inspect.
        
        Yields:
            Tuple containing information about each ETW consumer.
        """
        logger_ids = []
        for i, task in enumerate(tasks):
            layer_name = task.add_process_layer()
            layer = self.context.layers[layer_name]
            symbol_table = self.config['nt_symbols']
            if i == 0:
                vers = self.get_version_structure(self.context, layer_name, symbol_table)

            kvo = layer.config["kernel_virtual_offset"]
            ntkrnlmp = self.context.module(symbol_table, layer_name=layer_name, offset=kvo)
            hostsiloglobals_offset = ntkrnlmp.get_symbol("PspHostSiloGlobals").address
            serversilo_globals_entry = ntkrnlmp.object(object_type="_ESERVERSILO_GLOBALS",
                                                       offset=hostsiloglobals_offset)

            # Generate ETW logger context list
            try:
                etw_logger_context = self._generate_etw_logger_context(
                    vers, serversilo_globals_entry, ntkrnlmp)
            except:
                vollog.log(constants.LOGLEVEL_VVV,
                           f"Cannot load ETW stracture at {task.vol.offset:#x}")
                continue

            # Get the object type map and cookie
            try:
                type_map = handles.Handles.get_type_map(context=self.context,
                                                        layer_name=layer_name,
                                                        symbol_table=symbol_table)
                cookie = handles.Handles.find_cookie(context=self.context,
                                                     layer_name=layer_name,
                                                     symbol_table=symbol_table)
            except:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    "Cannot get type map or cookie",
                )
                continue

            try:
                object_table = task.ObjectTable
            except exceptions.InvalidAddressException:
                vollog.log(constants.LOGLEVEL_VVV,
                           f"Cannot access _EPROCESS.ObjectType at {task.vol.offset:#x}")
                continue

            for entry in self._handles(object_table, self.context, layer_name, symbol_table):
                try:
                    obj_type = entry.get_object_type(type_map, cookie)
                    if obj_type is None or obj_type != "EtwConsumer":
                        continue

                    consumer = entry.Body.cast("_ETW_REALTIME_CONSUMER")
                    logger_id = consumer.get_consumer_loggerid()
                    logger_ids.append(logger_id)
                    if 0 < logger_id < len(etw_logger_context):
                        logger_context = etw_logger_context[logger_id]
                        logger_name = logger_context.get_logger_name()
                        logfile_name = logger_context.get_log_filename()
                        consumer_guid = logger_context.get_guid()
                        logger_mode = logger_context.LoggerMode

                        # dump etl file from UserBufferListHead, BatchedBufferList, CompressionTarget, ScratchArray, BufferQueue
                        if self.config["alldump"]:
                            # dump etl file from UserBufferListHead
                            self._dump_etl_from_userbufferlist(logger_context, consumer,
                                                               logger_name, layer, layer_name,
                                                               ntkrnlmp)

                            # dump etl file from BatchedBufferList
                            if logger_context.get_buffers_written(
                            ) and logger_context.BatchedBufferList > 0:
                                self._dump_etl_from_offset(logger_context, logger_name, layer,
                                                           layer_name, ntkrnlmp,
                                                           logger_context.BatchedBufferList,
                                                           "batched")

                            # dump etl file from CompressionTarget
                            if logger_context.CompressionOn:
                                self._dump_etl_from_offset(logger_context, logger_name, layer,
                                                           layer_name, ntkrnlmp,
                                                           logger_context.CompressionTarget,
                                                           "compression")

                            # dump etl file from ScratchArray
                            if logger_context.ScratchArray > 0:
                                ScratchArray_table_ptr = ntkrnlmp.object(
                                    object_type="array",
                                    offset=logger_context.ScratchArray,
                                    subtype=ntkrnlmp.get_type("pointer"),
                                    count=40,
                                    absolute=True)
                                for ScratchArray_offset in ScratchArray_table_ptr:
                                    if ScratchArray_offset > 0:
                                        self._dump_etl_from_offset(logger_context, logger_name,
                                                                   layer, layer_name, ntkrnlmp,
                                                                   ScratchArray_offset, "scratch")

                            # dump etl file from BufferQueue
                            self._dump_etl_from_bufferqueue(logger_context, logger_name, layer,
                                                            layer_name, ntkrnlmp)

                            # dump etl file from OverflowQueue
                            self._dump_etl_from_overflowqueue(logger_context, logger_name, layer,
                                                              layer_name, ntkrnlmp)

                        # dump etl file
                        if self.config["dump"] or self.config["alldump"]:
                            # dump etl file from GlobalList
                            self._dump_etl_from_globallist(logger_context, logger_name, layer,
                                                           layer_name, ntkrnlmp)

                        yield (0, (task.UniqueProcessId,
                                   task.ImageFileName.cast("string",
                                                           max_length=task.ImageFileName.vol.count,
                                                           errors='replace'), obj_type, logger_id,
                                   logger_name, logfile_name, consumer_guid, hex(logger_mode)))

                except exceptions.InvalidAddressException:
                    vollog.log(constants.LOGLEVEL_VVV,
                               f"Cannot access _OBJECT_HEADER at {entry.vol.offset:#x}")
                    continue

        # Iterate through ETW logger contexts that were not matched to a task
        if not self.config.get('pid', None):
            for logger_id in range(1, len(etw_logger_context)):
                if logger_id not in logger_ids:
                    try:
                        logger_context = etw_logger_context[logger_id]
                        logger_name = logger_context.get_logger_name()
                        logfile_name = logger_context.get_log_filename()
                        consumer_guid = logger_context.get_guid()
                        logger_mode = logger_context.LoggerMode
                    except:
                        vollog.log(constants.LOGLEVEL_VVV,
                                   f"Cannot access _WMI_LOGGER_CONTEXT at {logger_id}")
                        continue

                    # dump etl file from BatchedBufferList, CompressionTarget, ScratchArray, BufferQueue
                    if self.config["alldump"]:
                        # dump etl file from BatchedBufferList
                        if logger_context.get_buffers_written(
                        ) and logger_context.BatchedBufferList > 0:
                            self._dump_etl_from_offset(logger_context, logger_name, layer,
                                                       layer_name, ntkrnlmp,
                                                       logger_context.BatchedBufferList, "batched")

                        # dump etl file from CompressionTarget
                        if logger_context.CompressionOn:
                            self._dump_etl_from_offset(logger_context, logger_name, layer,
                                                       layer_name, ntkrnlmp,
                                                       logger_context.CompressionTarget,
                                                       "compression")

                        # dump etl file from ScratchArray
                        if logger_context.ScratchArray > 0:
                            ScratchArray_table_ptr = ntkrnlmp.object(
                                object_type="array",
                                offset=logger_context.ScratchArray,
                                subtype=ntkrnlmp.get_type("pointer"),
                                count=32,
                                absolute=True)
                            for ScratchArray_offset in ScratchArray_table_ptr:
                                if ScratchArray_offset > 0:
                                    self._dump_etl_from_offset(logger_context, logger_name, layer,
                                                               layer_name, ntkrnlmp,
                                                               ScratchArray_offset, "scratch")

                        # dump etl file from BufferQueue
                        self._dump_etl_from_bufferqueue(logger_context, logger_name, layer,
                                                        layer_name, ntkrnlmp)

                        # dump etl file from OverflowQueue
                        self._dump_etl_from_overflowqueue(logger_context, logger_name, layer,
                                                          layer_name, ntkrnlmp)

                    if self.config["dump"] or self.config["alldump"]:
                        # dump etl file from GlobalList
                        self._dump_etl_from_globallist(logger_context, logger_name, layer,
                                                       layer_name, ntkrnlmp)

                    yield (0, (4, "System", "-", logger_id, logger_name, logfile_name,
                               consumer_guid, hex(logger_mode)))

    def run(self) -> renderers.TreeGrid:
        layer = self.context.layers[self.config['primary']]
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        # Ensure the layer is compatible with Windows OS
        if layer.metadata.get('os', None) in ['Windows', 'Unknown']:
            return renderers.TreeGrid([("PID", int), ("ImageFileName", str), ("TypeMap", str),
                                       ("LoggerId", int), ("LoggerName", str), ("LogFileName", str),
                                       ("Guid", str), ("Mode", str)],
                                      self._generator(
                                          pslist.PsList.list_processes(
                                              context=self.context,
                                              layer_name=self.config['primary'],
                                              symbol_table=self.config['nt_symbols'],
                                              filter_func=filter_func)))
        else:
            vollog.error("This command does not support the selected profile.")
