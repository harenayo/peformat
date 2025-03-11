const std = @import("std");

pub const Metadata = struct {
    root: Root,

    pub fn read(allocator: std.mem.Allocator, bytes: []const u8) !Metadata {
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

        var stream_headers = try std.ArrayList(StreamHeader).initCapacity(allocator, raw_metadata_root_1.Streams);

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

            const stream_header: StreamHeader = .{
                .offset = raw_stream_header_0.Offset,
                .size = raw_stream_header_0.Size,
                .name = name,
            };

            stream_headers.appendAssumeCapacity(stream_header);
        }

        const metadata_root: Root = .{
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
            .root = metadata_root,
        };
    }

    pub fn findStream(metadata: Metadata, kind: enum {
        string,
        us,
        blob,
        guid,
        table,
    }) ?StreamHeader {
        const name = switch (kind) {
            .string => "#Strings",
            .us => "#US",
            .blob => "#Blob",
            .guid => "#GUID",
            .table => "#~",
        };

        for (metadata.root.stream_headers.items) |stream_header| {
            if (!std.mem.eql(u8, stream_header.name.items, name)) continue;
            return stream_header;
        }

        return null;
    }

    pub fn free(metadata: Metadata) void {
        metadata.root.version.deinit();
        for (metadata.root.stream_headers.items) |stream_header| stream_header.name.deinit();
        metadata.root.stream_headers.deinit();
    }
};

pub const Root = struct {
    signature: u32,
    major_version: u16,
    minor_version: u16,
    reserved: u32,
    length: u32,
    version: std.ArrayList(u8),
    flags: u16,
    streams: u16,
    stream_headers: std.ArrayList(StreamHeader),
};

pub const StreamHeader = struct {
    offset: u32,
    size: u32,
    name: std.ArrayList(u8),
};

pub fn streamData(stream: StreamHeader, bytes: []const u8) []const u8 {
    return bytes[stream.offset..][0..stream.size];
}
