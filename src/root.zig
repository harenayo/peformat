const builtin = @import("builtin");
const std = @import("std");
const win32 = @import("win32");
pub const pe = @import("pe.zig");
pub const cli = @import("cli.zig");
pub const metadata = @import("metadata.zig");
pub const table_stream = @import("table_stream.zig");

test {
    const file = try std.fs.openFileAbsolute("C:\\Windows\\System32\\WinMetadata\\Windows.AI.winmd", .{});
    defer file.close();
    const pe_bytes = try file.readToEndAlloc(std.testing.allocator, std.math.maxInt(usize));
    defer std.testing.allocator.free(pe_bytes);
    const pe_data = try pe.Pe.read(std.testing.allocator, pe_bytes);
    defer pe_data.free();
    const cli_section = pe_data.findSection(pe_data.dataDirectory(std.coff.DirectoryEntry.COM_DESCRIPTOR).virtual_address) orelse return error.PeComDiscriptorNotFound;
    const cli_bytes = pe.sectionData(cli_section.header, pe_bytes)[cli_section.offset..];
    const cli_data = try cli.Cli.read(cli_bytes);
    const metadata_section = pe_data.findSection(cli_data.cor20_header.metadata.virtual_address) orelse return error.PeCliMetadataNotFound;
    const metadata_bytes = pe.sectionData(metadata_section.header, pe_bytes)[metadata_section.offset..];
    const metadata_data = try metadata.Metadata.read(std.testing.allocator, metadata_bytes);
    defer metadata_data.free();
    const tables_header = metadata_data.findStream(.table) orelse return error.PeTableStreamNotFound;
    const tables_data = metadata.streamData(tables_header, metadata_bytes);
    const tables = try table_stream.TableStream.read(std.testing.allocator, tables_data);
    defer tables.free();

    for (tables.tables.type_def.items) |type_def| {
        std.debug.print("{}\n", .{type_def});
    }
}
