const builtin = @import("builtin");
const std = @import("std");
const win32 = @import("win32");

pub const Cli = struct {
    cor20_header: Cor20Header,

    pub fn read(bytes: []const u8) !Cli {
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
