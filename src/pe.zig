const builtin = @import("builtin");
const std = @import("std");
const win32 = @import("win32");

pub const Pe = struct {
    dos_header: DosHeader,
    nt_signature: NtSignature,
    coff_header: std.coff.CoffHeader,
    optional_header: OptionalHeader,
    data_directories: [std.coff.IMAGE_NUMBEROF_DIRECTORY_ENTRIES]std.coff.ImageDataDirectory,
    section_headers: std.ArrayList(std.coff.SectionHeader),

    pub fn read(allocator: std.mem.Allocator, bytes: []const u8) !Pe {
        var stream = std.io.fixedBufferStream(bytes);
        const reader = stream.reader();
        const raw_dos_header = try reader.readStructEndian(win32.system.system_services.IMAGE_DOS_HEADER, .little);

        const dos_header: DosHeader = .{
            .magic = try std.meta.intToEnum(DosSignature, raw_dos_header.e_magic),
            .last_page_bytes = raw_dos_header.e_cblp,
            .pages = raw_dos_header.e_cp,
            .relocs_count = raw_dos_header.e_crlc,
            .paragraphs = raw_dos_header.e_cparhdr,
            .min_alloc = raw_dos_header.e_minalloc,
            .max_alloc = raw_dos_header.e_maxalloc,
            .ss = raw_dos_header.e_ss,
            .sp = raw_dos_header.e_sp,
            .check_sum = raw_dos_header.e_csum,
            .ip = raw_dos_header.e_ip,
            .cs = raw_dos_header.e_cs,
            .relocs_addr = raw_dos_header.e_lfarlc,
            .overlay = raw_dos_header.e_ovno,
            .reserved = raw_dos_header.e_res,
            .oem_id = raw_dos_header.e_oemid,
            .oem_info = raw_dos_header.e_oeminfo,
            .reserved2 = raw_dos_header.e_res2,
            .new_header_addr = @bitCast(raw_dos_header.e_lfanew),
        };

        try stream.seekTo(dos_header.new_header_addr);
        const raw_nt_signature = try reader.readInt(u32, .little);
        const nt_signature = try std.meta.intToEnum(NtSignature, raw_nt_signature);
        const raw_coff_header = try reader.readStructEndian(win32.system.diagnostics.debug.IMAGE_FILE_HEADER, .little);

        const coff_header: std.coff.CoffHeader = .{
            .machine = try std.meta.intToEnum(std.coff.MachineType, @intFromEnum(raw_coff_header.Machine)),
            .number_of_sections = raw_coff_header.NumberOfSections,
            .time_date_stamp = raw_coff_header.TimeDateStamp,
            .pointer_to_symbol_table = raw_coff_header.PointerToSymbolTable,
            .number_of_symbols = raw_coff_header.NumberOfSymbols,
            .size_of_optional_header = raw_coff_header.SizeOfOptionalHeader,
            .flags = @bitCast(raw_coff_header.Characteristics),
        };

        const optional_magic = try reader.readInt(u16, .little);
        try stream.seekBy(-@sizeOf(u16));

        const optional_header, const raw_data_directories = switch (optional_magic) {
            @intFromEnum(win32.system.diagnostics.debug.IMAGE_NT_OPTIONAL_HDR32_MAGIC) => blk: {
                const raw_optional_header_32 = try stream.reader().readStructEndian(win32.system.diagnostics.debug.IMAGE_OPTIONAL_HEADER32, .little);

                const optional_header_32: std.coff.OptionalHeaderPE32 = .{
                    .magic = @intFromEnum(raw_optional_header_32.Magic),
                    .major_linker_version = raw_optional_header_32.MajorLinkerVersion,
                    .minor_linker_version = raw_optional_header_32.MinorLinkerVersion,
                    .size_of_code = raw_optional_header_32.SizeOfCode,
                    .size_of_initialized_data = raw_optional_header_32.SizeOfInitializedData,
                    .size_of_uninitialized_data = raw_optional_header_32.SizeOfUninitializedData,
                    .address_of_entry_point = raw_optional_header_32.AddressOfEntryPoint,
                    .base_of_code = raw_optional_header_32.BaseOfCode,
                    .base_of_data = raw_optional_header_32.BaseOfData,
                    .image_base = raw_optional_header_32.ImageBase,
                    .section_alignment = raw_optional_header_32.SectionAlignment,
                    .file_alignment = raw_optional_header_32.FileAlignment,
                    .major_operating_system_version = raw_optional_header_32.MajorOperatingSystemVersion,
                    .minor_operating_system_version = raw_optional_header_32.MinorOperatingSystemVersion,
                    .major_image_version = raw_optional_header_32.MajorImageVersion,
                    .minor_image_version = raw_optional_header_32.MinorImageVersion,
                    .major_subsystem_version = raw_optional_header_32.MajorSubsystemVersion,
                    .minor_subsystem_version = raw_optional_header_32.MinorSubsystemVersion,
                    .win32_version_value = raw_optional_header_32.Win32VersionValue,
                    .size_of_image = raw_optional_header_32.SizeOfImage,
                    .size_of_headers = raw_optional_header_32.SizeOfHeaders,
                    .checksum = raw_optional_header_32.CheckSum,
                    .subsystem = try std.meta.intToEnum(std.coff.Subsystem, @intFromEnum(raw_optional_header_32.Subsystem)),
                    .dll_flags = @bitCast(raw_optional_header_32.DllCharacteristics),
                    .size_of_stack_reserve = raw_optional_header_32.SizeOfStackReserve,
                    .size_of_stack_commit = raw_optional_header_32.SizeOfStackCommit,
                    .size_of_heap_reserve = raw_optional_header_32.SizeOfHeapReserve,
                    .size_of_heap_commit = raw_optional_header_32.SizeOfHeapCommit,
                    .loader_flags = raw_optional_header_32.LoaderFlags,
                    .number_of_rva_and_sizes = raw_optional_header_32.NumberOfRvaAndSizes,
                };

                const optional_header: OptionalHeader = .{
                    .@"32" = optional_header_32,
                };

                const raw_data_directories = raw_optional_header_32.DataDirectory;

                break :blk .{
                    optional_header,
                    raw_data_directories,
                };
            },
            @intFromEnum(win32.system.diagnostics.debug.IMAGE_NT_OPTIONAL_HDR64_MAGIC) => blk: {
                const raw_optional_header_64 = try stream.reader().readStructEndian(win32.system.diagnostics.debug.IMAGE_OPTIONAL_HEADER64, .little);

                const optional_header_64: std.coff.OptionalHeaderPE64 = .{
                    .magic = @intFromEnum(raw_optional_header_64.Magic),
                    .major_linker_version = raw_optional_header_64.MajorLinkerVersion,
                    .minor_linker_version = raw_optional_header_64.MinorLinkerVersion,
                    .size_of_code = raw_optional_header_64.SizeOfCode,
                    .size_of_initialized_data = raw_optional_header_64.SizeOfInitializedData,
                    .size_of_uninitialized_data = raw_optional_header_64.SizeOfUninitializedData,
                    .address_of_entry_point = raw_optional_header_64.AddressOfEntryPoint,
                    .base_of_code = raw_optional_header_64.BaseOfCode,
                    .image_base = raw_optional_header_64.ImageBase,
                    .section_alignment = raw_optional_header_64.SectionAlignment,
                    .file_alignment = raw_optional_header_64.FileAlignment,
                    .major_operating_system_version = raw_optional_header_64.MajorOperatingSystemVersion,
                    .minor_operating_system_version = raw_optional_header_64.MinorOperatingSystemVersion,
                    .major_image_version = raw_optional_header_64.MajorImageVersion,
                    .minor_image_version = raw_optional_header_64.MinorImageVersion,
                    .major_subsystem_version = raw_optional_header_64.MajorSubsystemVersion,
                    .minor_subsystem_version = raw_optional_header_64.MinorSubsystemVersion,
                    .win32_version_value = raw_optional_header_64.Win32VersionValue,
                    .size_of_image = raw_optional_header_64.SizeOfImage,
                    .size_of_headers = raw_optional_header_64.SizeOfHeaders,
                    .checksum = raw_optional_header_64.CheckSum,
                    .subsystem = try std.meta.intToEnum(std.coff.Subsystem, @intFromEnum(raw_optional_header_64.Subsystem)),
                    .dll_flags = @bitCast(raw_optional_header_64.DllCharacteristics),
                    .size_of_stack_reserve = raw_optional_header_64.SizeOfStackReserve,
                    .size_of_stack_commit = raw_optional_header_64.SizeOfStackCommit,
                    .size_of_heap_reserve = raw_optional_header_64.SizeOfHeapReserve,
                    .size_of_heap_commit = raw_optional_header_64.SizeOfHeapCommit,
                    .loader_flags = raw_optional_header_64.LoaderFlags,
                    .number_of_rva_and_sizes = raw_optional_header_64.NumberOfRvaAndSizes,
                };

                const optional_header: OptionalHeader = .{
                    .@"64" = optional_header_64,
                };

                const raw_data_directories = raw_optional_header_64.DataDirectory;

                break :blk .{
                    optional_header,
                    raw_data_directories,
                };
            },
            else => return error.PeInvalidOptionalMagic,
        };

        var data_directories: [std.coff.IMAGE_NUMBEROF_DIRECTORY_ENTRIES]std.coff.ImageDataDirectory = undefined;

        for (&data_directories, raw_data_directories) |*data_directory_ptr, raw_data_directory| {
            data_directory_ptr.* = .{
                .virtual_address = raw_data_directory.VirtualAddress,
                .size = raw_data_directory.Size,
            };
        }

        var section_headers = try std.ArrayList(std.coff.SectionHeader).initCapacity(allocator, coff_header.number_of_sections);
        errdefer section_headers.deinit();

        for (0..section_headers.capacity) |_| {
            var raw_section_header = try reader.readStruct(win32.system.diagnostics.debug.IMAGE_SECTION_HEADER);

            if (builtin.target.cpu.arch.endian() == .big) {
                raw_section_header.Misc.VirtualSize = @byteSwap(raw_section_header.Misc.VirtualSize);
                raw_section_header.VirtualAddress = @byteSwap(raw_section_header.VirtualAddress);
                raw_section_header.SizeOfRawData = @byteSwap(raw_section_header.SizeOfRawData);
                raw_section_header.PointerToRawData = @byteSwap(raw_section_header.PointerToRawData);
                raw_section_header.PointerToRelocations = @byteSwap(raw_section_header.PointerToRelocations);
                raw_section_header.PointerToLinenumbers = @byteSwap(raw_section_header.PointerToLinenumbers);
                raw_section_header.NumberOfRelocations = @byteSwap(raw_section_header.NumberOfRelocations);
                raw_section_header.NumberOfLinenumbers = @byteSwap(raw_section_header.NumberOfLinenumbers);
                raw_section_header.Characteristics = @bitCast(@byteSwap(@as(u32, @bitCast(raw_section_header.Characteristics))));
            }

            const section_header: std.coff.SectionHeader = .{
                .name = raw_section_header.Name,
                .virtual_size = raw_section_header.Misc.VirtualSize,
                .virtual_address = raw_section_header.VirtualAddress,
                .size_of_raw_data = raw_section_header.SizeOfRawData,
                .pointer_to_raw_data = raw_section_header.PointerToRawData,
                .pointer_to_relocations = raw_section_header.PointerToRelocations,
                .pointer_to_linenumbers = raw_section_header.PointerToLinenumbers,
                .number_of_relocations = raw_section_header.NumberOfRelocations,
                .number_of_linenumbers = raw_section_header.NumberOfLinenumbers,
                .flags = @bitCast(raw_section_header.Characteristics),
            };

            section_headers.appendAssumeCapacity(section_header);
        }

        return .{
            .dos_header = dos_header,
            .nt_signature = nt_signature,
            .coff_header = coff_header,
            .optional_header = optional_header,
            .data_directories = data_directories,
            .section_headers = section_headers,
        };
    }

    pub fn dataDirectory(pe: Pe, entry: std.coff.DirectoryEntry) std.coff.ImageDataDirectory {
        return pe.data_directories[@intFromEnum(entry)];
    }

    pub fn findSection(pe: Pe, virtual_address: u32) ?struct {
        header: std.coff.SectionHeader,
        offset: u32,
    } {
        for (pe.section_headers.items) |section_header| {
            if (virtual_address < section_header.virtual_address) continue;
            const offset = virtual_address - section_header.virtual_address;
            if (offset >= section_header.size_of_raw_data) continue;

            return .{
                .header = section_header,
                .offset = virtual_address - section_header.virtual_address,
            };
        }

        return null;
    }

    pub fn free(pe: Pe) void {
        pe.section_headers.deinit();
    }
};

pub const DosHeader = struct {
    magic: DosSignature,
    last_page_bytes: u16,
    pages: u16,
    relocs_count: u16,
    paragraphs: u16,
    min_alloc: u16,
    max_alloc: u16,
    ss: u16,
    sp: u16,
    check_sum: u16,
    ip: u16,
    cs: u16,
    relocs_addr: u16,
    overlay: u16,
    reserved: [4]u16,
    oem_id: u16,
    oem_info: u16,
    reserved2: [10]u16,
    new_header_addr: u32,
};

pub const DosSignature = enum(u16) {
    dos_signature = win32.system.system_services.IMAGE_DOS_SIGNATURE,
};

pub const NtSignature = enum(u32) {
    nt_signature = win32.system.system_services.IMAGE_NT_SIGNATURE,
};

pub const OptionalHeader = union(enum) {
    @"32": std.coff.OptionalHeaderPE32,
    @"64": std.coff.OptionalHeaderPE64,
};

pub fn sectionData(section: std.coff.SectionHeader, bytes: []const u8) []const u8 {
    return bytes[section.pointer_to_raw_data..][0..section.size_of_raw_data];
}
