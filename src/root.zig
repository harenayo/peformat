const builtin = @import("builtin");
const std = @import("std");
const win32 = @import("win32");

pub const Pe = struct {
    dos_header: DosHeader,
    nt_signature: u32,
    coff_header: std.coff.CoffHeader,
    optional_header: OptionalHeader,
    data_directories: [std.coff.IMAGE_NUMBEROF_DIRECTORY_ENTRIES]std.coff.ImageDataDirectory,
    section_headers: std.ArrayList(std.coff.SectionHeader),

    fn read(allocator: std.mem.Allocator, bytes: []const u8) !Pe {
        var stream = std.io.fixedBufferStream(bytes);
        const reader = stream.reader();
        const raw_dos_header = try reader.readStructEndian(win32.system.system_services.IMAGE_DOS_HEADER, .little);

        const dos_header: DosHeader = .{
            .magic = raw_dos_header.e_magic,
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

        if (dos_header.magic != win32.system.system_services.IMAGE_DOS_SIGNATURE) return error.PeInvalidDosSignature;
        try stream.seekTo(dos_header.new_header_addr);
        const nt_signature = try reader.readInt(u32, .little);
        if (nt_signature != win32.system.system_services.IMAGE_NT_SIGNATURE) return error.PeInvalidNtSignature;
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

    fn data_directory(pe: Pe, entry: std.coff.DirectoryEntry) std.coff.ImageDataDirectory {
        return pe.data_directories[@intFromEnum(entry)];
    }

    fn find_section(pe: Pe, virtual_address: u32) ?struct {
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

    fn free(pe: Pe) void {
        pe.section_headers.deinit();
    }

    fn section_data(section: std.coff.SectionHeader, bytes: []const u8) []const u8 {
        return bytes[section.pointer_to_raw_data..][0..section.size_of_raw_data];
    }
};

pub const DosHeader = struct {
    magic: u16,
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

pub const OptionalHeader = union(enum) {
    @"32": std.coff.OptionalHeaderPE32,
    @"64": std.coff.OptionalHeaderPE64,
};

pub const Cli = struct {
    cor20_header: Cor20Header,

    fn read(bytes: []const u8) !Cli {
        var stream = std.io.fixedBufferStream(bytes);
        const reader = stream.reader();
        var raw_cor20_header = try reader.readStruct(win32.system.diagnostics.debug.IMAGE_COR20_HEADER);
        const swap_bytes = builtin.target.cpu.arch.endian() == .big;

        if (swap_bytes) {
            raw_cor20_header.cb = @byteSwap(raw_cor20_header.cb);
            raw_cor20_header.MajorRuntimeVersion = @byteSwap(raw_cor20_header.MajorRuntimeVersion);
            raw_cor20_header.MinorRuntimeVersion = @byteSwap(raw_cor20_header.MinorRuntimeVersion);
            raw_cor20_header.MetaData.VirtualAddress = @byteSwap(raw_cor20_header.MetaData.VirtualAddress);
            raw_cor20_header.MetaData.Size = @byteSwap(raw_cor20_header.MetaData.Size);
            raw_cor20_header.Flags = @byteSwap(raw_cor20_header.Flags);
        }

        const native_entry_point = raw_cor20_header.Flags & @intFromEnum(win32.system.system_services.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) != 0;

        if (swap_bytes) {
            switch (native_entry_point) {
                false => raw_cor20_header.Anonymous.EntryPointToken = @byteSwap(raw_cor20_header.Anonymous.EntryPointToken),
                true => raw_cor20_header.Anonymous.EntryPointRVA = @byteSwap(raw_cor20_header.Anonymous.EntryPointRVA),
            }

            raw_cor20_header.Resources.VirtualAddress = @byteSwap(raw_cor20_header.Resources.VirtualAddress);
            raw_cor20_header.Resources.Size = @byteSwap(raw_cor20_header.Resources.Size);
            raw_cor20_header.StrongNameSignature.VirtualAddress = @byteSwap(raw_cor20_header.StrongNameSignature.VirtualAddress);
            raw_cor20_header.StrongNameSignature.Size = @byteSwap(raw_cor20_header.StrongNameSignature.Size);
            raw_cor20_header.CodeManagerTable.VirtualAddress = @byteSwap(raw_cor20_header.CodeManagerTable.VirtualAddress);
            raw_cor20_header.CodeManagerTable.Size = @byteSwap(raw_cor20_header.CodeManagerTable.Size);
            raw_cor20_header.VTableFixups.VirtualAddress = @byteSwap(raw_cor20_header.VTableFixups.VirtualAddress);
            raw_cor20_header.VTableFixups.Size = @byteSwap(raw_cor20_header.VTableFixups.Size);
            raw_cor20_header.ExportAddressTableJumps.VirtualAddress = @byteSwap(raw_cor20_header.ExportAddressTableJumps.VirtualAddress);
            raw_cor20_header.ExportAddressTableJumps.Size = @byteSwap(raw_cor20_header.ExportAddressTableJumps.Size);
            raw_cor20_header.ManagedNativeHeader.VirtualAddress = @byteSwap(raw_cor20_header.ManagedNativeHeader.VirtualAddress);
            raw_cor20_header.ManagedNativeHeader.Size = @byteSwap(raw_cor20_header.ManagedNativeHeader.Size);
        }

        const cor20_header: Cor20Header = .{
            .size = raw_cor20_header.cb,
            .major_runtime_version = raw_cor20_header.MajorRuntimeVersion,
            .minor_runtime_version = raw_cor20_header.MinorRuntimeVersion,
            .metadata = .{
                .virtual_address = raw_cor20_header.MetaData.VirtualAddress,
                .size = raw_cor20_header.MetaData.Size,
            },
            .flags = raw_cor20_header.Flags,
            .anonymous = switch (native_entry_point) {
                false => .{ .entry_point_token = raw_cor20_header.Anonymous.EntryPointToken },
                true => .{ .entry_point_rva = raw_cor20_header.Anonymous.EntryPointRVA },
            },
            .resources = .{
                .virtual_address = raw_cor20_header.Resources.VirtualAddress,
                .size = raw_cor20_header.Resources.Size,
            },
            .strong_name_signature = .{
                .virtual_address = raw_cor20_header.StrongNameSignature.VirtualAddress,
                .size = raw_cor20_header.StrongNameSignature.Size,
            },
            .code_manager_table = .{
                .virtual_address = raw_cor20_header.CodeManagerTable.VirtualAddress,
                .size = raw_cor20_header.CodeManagerTable.Size,
            },
            .vtable_fixups = .{
                .virtual_address = raw_cor20_header.VTableFixups.VirtualAddress,
                .size = raw_cor20_header.VTableFixups.Size,
            },
            .export_address_table_jumps = .{
                .virtual_address = raw_cor20_header.ExportAddressTableJumps.VirtualAddress,
                .size = raw_cor20_header.ExportAddressTableJumps.Size,
            },
            .managed_native_header = .{
                .virtual_address = raw_cor20_header.ManagedNativeHeader.VirtualAddress,
                .size = raw_cor20_header.ManagedNativeHeader.Size,
            },
        };

        return .{
            .cor20_header = cor20_header,
        };
    }
};

pub const Cor20Header = struct {
    size: u32,
    major_runtime_version: u16,
    minor_runtime_version: u16,
    metadata: std.coff.ImageDataDirectory,
    flags: u32,
    anonymous: union(enum) {
        entry_point_token: u32,
        entry_point_rva: u32,
    },
    resources: std.coff.ImageDataDirectory,
    strong_name_signature: std.coff.ImageDataDirectory,
    code_manager_table: std.coff.ImageDataDirectory,
    vtable_fixups: std.coff.ImageDataDirectory,
    export_address_table_jumps: std.coff.ImageDataDirectory,
    managed_native_header: std.coff.ImageDataDirectory,
};

pub const CliMetadata = struct {
    metadata_root: CliMetadataRoot,

    fn read(allocator: std.mem.Allocator, bytes: []const u8) !CliMetadata {
        var stream = std.io.fixedBufferStream(bytes);
        const reader = stream.reader();

        const raw_metadata_root_0 = try reader.readStructEndian(extern struct {
            Signature: u32,
            MajorVersion: u16,
            MinorVersion: u16,
            Reserved: u32,
            Length: u32,
        }, .little);

        if (raw_metadata_root_0.Signature != 0x424A5342) return error.PeInvalidCliMetadataSignature;
        var version = try std.ArrayList(u8).initCapacity(allocator, raw_metadata_root_0.Length - 1);
        errdefer version.deinit();
        try reader.streamUntilDelimiter(version.writer(), 0, raw_metadata_root_0.Length);
        try stream.seekBy(raw_metadata_root_0.Length - @as(u32, @intCast(version.items.len)) - 1);

        const raw_metadata_root_1 = try stream.reader().readStructEndian(extern struct {
            Flags: u16,
            Streams: u16,
        }, .little);

        var stream_headers = try std.ArrayList(CliStreamHeader).initCapacity(allocator, raw_metadata_root_1.Streams);

        errdefer {
            for (stream_headers.items) |stream_header| stream_header.name.deinit();
            stream_headers.deinit();
        }

        for (0..raw_metadata_root_1.Streams) |_| {
            const raw_stream_header_0 = try stream.reader().readStructEndian(extern struct {
                Offset: u32,
                Size: u32,
            }, .little);

            var name = std.ArrayList(u8).init(allocator);
            errdefer name.deinit();
            try stream.reader().streamUntilDelimiter(name.writer(), 0, null);
            const padding = 4 - (name.items.len + 1) % 4;
            if (padding != 4) try stream.seekBy(@intCast(padding));

            const stream_header: CliStreamHeader = .{
                .offset = raw_stream_header_0.Offset,
                .size = raw_stream_header_0.Size,
                .name = name,
            };

            stream_headers.appendAssumeCapacity(stream_header);
        }

        const metadata_root: CliMetadataRoot = .{
            .signature = raw_metadata_root_0.Signature,
            .major_version = raw_metadata_root_0.MajorVersion,
            .minor_version = raw_metadata_root_0.MinorVersion,
            .reserved = raw_metadata_root_0.Reserved,
            .length = raw_metadata_root_0.Length,
            .version = version,
            .flags = raw_metadata_root_1.Flags,
            .streams = raw_metadata_root_1.Streams,
            .stream_headers = stream_headers,
        };

        return .{
            .metadata_root = metadata_root,
        };
    }

    fn find_stream(metadata: CliMetadata, kind: enum {
        string,
        us,
        blob,
        guid,
        table,
    }) ?usize {
        const name = switch (kind) {
            .string => "#Strings",
            .us => "#US",
            .blob => "#Blob",
            .guid => "#GUID",
            .table => "#~",
        };

        for (0.., metadata.metadata_root.stream_headers.items) |i, stream_header| {
            if (!std.mem.eql(u8, stream_header.name.items, name)) continue;
            return i;
        }

        return null;
    }

    fn free(metadata: CliMetadata) void {
        metadata.metadata_root.version.deinit();
        for (metadata.metadata_root.stream_headers.items) |stream_header| stream_header.name.deinit();
        metadata.metadata_root.stream_headers.deinit();
    }

    fn stream_data(stream: CliStreamHeader, bytes: []const u8) []const u8 {
        return bytes[stream.offset..][0..stream.size];
    }
};

pub const CliMetadataRoot = struct {
    signature: u32,
    major_version: u16,
    minor_version: u16,
    reserved: u32,
    length: u32,
    version: std.ArrayList(u8),
    flags: u16,
    streams: u16,
    stream_headers: std.ArrayList(CliStreamHeader),
};

pub const CliStreamHeader = struct {
    offset: u32,
    size: u32,
    name: std.ArrayList(u8),
};

test {
    const file = try std.fs.openFileAbsolute("C:\\Windows\\System32\\WinMetadata\\Windows.AI.winmd", .{});
    defer file.close();
    const pe_data = try file.readToEndAlloc(std.testing.allocator, std.math.maxInt(usize));
    defer std.testing.allocator.free(pe_data);
    const pe = try Pe.read(std.testing.allocator, pe_data);
    defer pe.free();
    const cli_section = pe.find_section(pe.data_directory(std.coff.DirectoryEntry.COM_DESCRIPTOR).virtual_address) orelse return error.PeComDiscriptorNotFound;
    const cli_data = Pe.section_data(cli_section.header, pe_data)[cli_section.offset..];
    const cli = try Cli.read(cli_data);
    const metadata_section = pe.find_section(cli.cor20_header.metadata.virtual_address) orelse return error.PeCliMetadataNotFound;
    const metadata_data = Pe.section_data(metadata_section.header, pe_data)[metadata_section.offset..];
    const metadata = try CliMetadata.read(std.testing.allocator, metadata_data);
    defer metadata.free();
    for (pe.section_headers.items) |section_header| std.debug.print("{?s}\n", .{section_header.getName()});
    std.debug.print("{s}\n", .{metadata.metadata_root.version.items});
    for (metadata.metadata_root.stream_headers.items) |stream_header| std.debug.print("{s}\n", .{stream_header.name.items});
}
