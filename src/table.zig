const std = @import("std");

pub const Heap = enum {
    string,
    guid,
    blob,

    const properties: std.enums.EnumFieldStruct(Heap, u8, null) = .{
        .string = 0x01,
        .guid = 0x02,
        .blob = 0x04,
    };

    pub fn flagBit(comptime heap: Heap) u8 {
        return @field(properties, @tagName(heap));
    }
};

pub const Table = enum {
    module,
    type_ref,
    type_def,
    field,
    method_def,
    param,
    interface_impl,
    member_ref,
    constant,
    custom_attribute,
    field_marshal,
    decl_security,
    class_layout,
    field_layout,
    stand_alone_sig,
    event_map,
    event,
    property_map,
    property,
    method_semantics,
    method_impl,
    module_ref,
    type_spec,
    impl_map,
    field_rva,
    assembly,
    assembly_processor,
    assembly_os,
    assembly_ref,
    assembly_ref_processor,
    assembly_ref_os,
    file,
    exported_type,
    manifest_resource,
    nested_class,
    generic_param,
    method_spec,
    generic_param_constraint,

    const properties: std.enums.EnumFieldStruct(Table, struct { u6, type }, null) = .{
        .module = .{ 0x00, ModuleColumn },
        .type_ref = .{ 0x01, TypeRefColumn },
        .type_def = .{ 0x02, TypeDefColumn },
        .field = .{ 0x04, FieldColumn },
        .method_def = .{ 0x06, MethodDefColumn },
        .param = .{ 0x08, ParamColumn },
        .interface_impl = .{ 0x09, InterfaceImplColumn },
        .member_ref = .{ 0x0A, MemberRefColumn },
        .constant = .{ 0x0B, ConstantColumn },
        .custom_attribute = .{ 0x0C, CustomAttributeColumn },
        .field_marshal = .{ 0x0D, FieldMarshalColumn },
        .decl_security = .{ 0x0E, DeclSecurityColumn },
        .class_layout = .{ 0x0F, ClassLayoutColumn },
        .field_layout = .{ 0x10, FieldLayoutColumn },
        .stand_alone_sig = .{ 0x11, StandAloneSigColumn },
        .event_map = .{ 0x12, EventMapColumn },
        .event = .{ 0x14, EventColumn },
        .property_map = .{ 0x15, PropertyMapColumn },
        .property = .{ 0x17, PropertyColumn },
        .method_semantics = .{ 0x18, MethodSemanticsColumn },
        .method_impl = .{ 0x19, MethodImplColumn },
        .module_ref = .{ 0x1A, ModuleRefColumn },
        .type_spec = .{ 0x1B, TypeSpecColumn },
        .impl_map = .{ 0x1C, ImplMapColumn },
        .field_rva = .{ 0x1D, FieldRvaColumn },
        .assembly = .{ 0x20, AssemblyColumn },
        .assembly_processor = .{ 0x21, AssemblyProcessorColumn },
        .assembly_os = .{ 0x22, AssemblyOsColumn },
        .assembly_ref = .{ 0x23, AssemblyRefColumn },
        .assembly_ref_processor = .{ 0x24, AssemblyRefProcessorColumn },
        .assembly_ref_os = .{ 0x25, AssemblyRefOsColumn },
        .file = .{ 0x26, FileColumn },
        .exported_type = .{ 0x27, ExportedTypeColumn },
        .manifest_resource = .{ 0x28, ManifestResourceColumn },
        .nested_class = .{ 0x29, NestedClassColumn },
        .generic_param = .{ 0x2A, GenericParamColumn },
        .method_spec = .{ 0x2B, MethodSpecColumn },
        .generic_param_constraint = .{ 0x2C, GenericParamConstraintColumn },
    };

    pub fn number(comptime table: Table) u6 {
        return @field(properties, @tagName(table))[0];
    }

    pub fn Column(table: Table) type {
        return @field(properties, @tagName(table))[1];
    }

    pub fn validBit(comptime table: Table) u64 {
        return @as(u64, 1) << table.number();
    }

    pub fn Data(table: Table, column: table.Column()) type {
        return @field(table.Column().properties, @tagName(column));
    }

    pub fn Row(table: Table) type {
        const columns = std.meta.tags(table.Column());
        var row_fields: [columns.len]std.builtin.Type.StructField = undefined;

        for (&row_fields, columns) |*row_field, column| {
            const Type = table.Data(column).Type;

            row_field.* = .{
                .name = @tagName(column),
                .type = Type,
                .default_value_ptr = null,
                .is_comptime = false,
                .alignment = @alignOf(Type),
            };
        }

        return @Type(.{ .@"struct" = .{
            .layout = .auto,
            .fields = &row_fields,
            .decls = &.{},
            .is_tuple = false,
        } });
    }

    pub fn readRow(comptime table: Table, stream: *std.io.FixedBufferStream([]const u8), sizes: IndexSizes) !table.Row() {
        var row: table.Row() = undefined;

        inline for (comptime std.meta.tags(table.Column())) |column| {
            @field(row, @tagName(column)) = try table.Data(column).read(stream, sizes);
        }

        return row;
    }
};

pub const ModuleColumn = enum {
    generation,
    name,
    mvid,
    enc_id,
    enc_base_id,

    const properties: std.enums.EnumFieldStruct(ModuleColumn, type, null) = .{
        .generation = IntData(2),
        .name = IndexData(.{ .heap = .string }),
        .mvid = IndexData(.{ .heap = .guid }),
        .enc_id = IndexData(.{ .heap = .guid }),
        .enc_base_id = IndexData(.{ .heap = .guid }),
    };
};

pub const TypeRefColumn = enum {
    resolution_scope,
    type_name,
    type_namespace,

    const properties: std.enums.EnumFieldStruct(TypeRefColumn, type, null) = .{
        .resolution_scope = CodedIndexData(.resolution_scope),
        .type_name = IndexData(.{ .heap = .string }),
        .type_namespace = IndexData(.{ .heap = .string }),
    };
};

pub const TypeDefColumn = enum {
    flags,
    type_name,
    type_namespace,
    extends,
    field_list,
    method_list,

    const properties: std.enums.EnumFieldStruct(TypeDefColumn, type, null) = .{
        .flags = IntData(4),
        .type_name = IndexData(.{ .heap = .string }),
        .type_namespace = IndexData(.{ .heap = .string }),
        .extends = CodedIndexData(.type_def_or_ref),
        .field_list = IndexData(.{ .table = .field }),
        .method_list = IndexData(.{ .table = .method_def }),
    };
};

pub const FieldColumn = enum {
    flags,
    name,
    signature,

    const properties: std.enums.EnumFieldStruct(FieldColumn, type, null) = .{
        .flags = IntData(2),
        .name = IndexData(.{ .heap = .string }),
        .signature = IndexData(.{ .heap = .blob }),
    };
};

pub const MethodDefColumn = enum {
    rva,
    impl_flags,
    flags,
    name,
    signature,
    param_list,

    const properties: std.enums.EnumFieldStruct(MethodDefColumn, type, null) = .{
        .rva = IntData(4),
        .impl_flags = IntData(2),
        .flags = IntData(2),
        .name = IndexData(.{ .heap = .string }),
        .signature = IndexData(.{ .heap = .blob }),
        .param_list = IndexData(.{ .table = .param }),
    };
};

pub const ParamColumn = enum {
    flags,
    sequence,
    name,

    const properties: std.enums.EnumFieldStruct(ParamColumn, type, null) = .{
        .flags = IntData(2),
        .sequence = IntData(2),
        .name = IndexData(.{ .heap = .string }),
    };
};

pub const InterfaceImplColumn = enum {
    class,
    interface,

    const properties: std.enums.EnumFieldStruct(InterfaceImplColumn, type, null) = .{
        .class = IndexData(.{ .table = .type_def }),
        .interface = CodedIndexData(.type_def_or_ref),
    };
};

pub const MemberRefColumn = enum {
    class,
    name,
    signature,

    const properties: std.enums.EnumFieldStruct(MemberRefColumn, type, null) = .{
        .class = CodedIndexData(.member_ref_parent),
        .name = IndexData(.{ .heap = .string }),
        .signature = IndexData(.{ .heap = .blob }),
    };
};

pub const ConstantColumn = enum {
    type,
    parent,
    value,

    const properties: std.enums.EnumFieldStruct(ConstantColumn, type, null) = .{
        .type = IntData(2),
        .parent = CodedIndexData(.has_constant),
        .value = IndexData(.{ .heap = .blob }),
    };
};

pub const CustomAttributeColumn = enum {
    parent,
    type,
    value,

    const properties: std.enums.EnumFieldStruct(CustomAttributeColumn, type, null) = .{
        .parent = CodedIndexData(.has_custom_attribute),
        .type = CodedIndexData(.custom_attribute_type),
        .value = IndexData(.{ .heap = .blob }),
    };
};

pub const FieldMarshalColumn = enum {
    parent,
    native_type,

    const properties: std.enums.EnumFieldStruct(FieldMarshalColumn, type, null) = .{
        .parent = CodedIndexData(.has_field_marshal),
        .native_type = IndexData(.{ .heap = .blob }),
    };
};

pub const DeclSecurityColumn = enum {
    action,
    parent,
    permission_set,

    const properties: std.enums.EnumFieldStruct(DeclSecurityColumn, type, null) = .{
        .action = IntData(2),
        .parent = CodedIndexData(.has_decl_security),
        .permission_set = IndexData(.{ .heap = .blob }),
    };
};

pub const ClassLayoutColumn = enum {
    packing_size,
    class_size,
    parent,

    const properties: std.enums.EnumFieldStruct(ClassLayoutColumn, type, null) = .{
        .packing_size = IntData(2),
        .class_size = IntData(4),
        .parent = IndexData(.{ .table = .type_def }),
    };
};

pub const FieldLayoutColumn = enum {
    offset,
    field,

    const properties: std.enums.EnumFieldStruct(FieldLayoutColumn, type, null) = .{
        .offset = IntData(4),
        .field = IndexData(.{ .table = .field }),
    };
};

pub const StandAloneSigColumn = enum {
    signature,

    const properties: std.enums.EnumFieldStruct(StandAloneSigColumn, type, null) = .{
        .signature = IndexData(.{ .heap = .blob }),
    };
};

pub const EventMapColumn = enum {
    parent,
    event_list,

    const properties: std.enums.EnumFieldStruct(EventMapColumn, type, null) = .{
        .parent = IndexData(.{ .table = .type_def }),
        .event_list = IndexData(.{ .table = .event }),
    };
};

pub const EventColumn = enum {
    event_flags,
    name,
    event_type,

    const properties: std.enums.EnumFieldStruct(EventColumn, type, null) = .{
        .event_flags = IntData(2),
        .name = IndexData(.{ .heap = .string }),
        .event_type = CodedIndexData(.type_def_or_ref),
    };
};

pub const PropertyMapColumn = enum {
    parent,
    property_list,

    const properties: std.enums.EnumFieldStruct(PropertyMapColumn, type, null) = .{
        .parent = IndexData(.{ .table = .type_def }),
        .property_list = IndexData(.{ .table = .property }),
    };
};

pub const PropertyColumn = enum {
    flags,
    name,
    type,

    const properties: std.enums.EnumFieldStruct(PropertyColumn, type, null) = .{
        .flags = IntData(2),
        .name = IndexData(.{ .heap = .string }),
        .type = IndexData(.{ .heap = .blob }),
    };
};

pub const MethodSemanticsColumn = enum {
    semantics,
    method,
    association,

    const properties: std.enums.EnumFieldStruct(MethodSemanticsColumn, type, null) = .{
        .semantics = IntData(2),
        .method = IndexData(.{ .table = .method_def }),
        .association = CodedIndexData(.has_semantics),
    };
};

pub const MethodImplColumn = enum {
    class,
    method_body,
    method_declaration,

    const properties: std.enums.EnumFieldStruct(MethodImplColumn, type, null) = .{
        .class = IndexData(.{ .table = .type_def }),
        .method_body = CodedIndexData(.method_def_or_ref),
        .method_declaration = CodedIndexData(.method_def_or_ref),
    };
};

pub const ModuleRefColumn = enum {
    name,

    const properties: std.enums.EnumFieldStruct(ModuleRefColumn, type, null) = .{
        .name = IndexData(.{ .heap = .string }),
    };
};

pub const TypeSpecColumn = enum {
    signature,

    const properties: std.enums.EnumFieldStruct(TypeSpecColumn, type, null) = .{
        .signature = IndexData(.{ .heap = .blob }),
    };
};

pub const ImplMapColumn = enum {
    mapping_flags,
    member_forwarded,
    import_name,
    import_scope,

    const properties: std.enums.EnumFieldStruct(ImplMapColumn, type, null) = .{
        .mapping_flags = IntData(2),
        .member_forwarded = CodedIndexData(.member_forwarded),
        .import_name = IndexData(.{ .heap = .string }),
        .import_scope = IndexData(.{ .table = .module_ref }),
    };
};

pub const FieldRvaColumn = enum {
    rva,
    field,

    const properties: std.enums.EnumFieldStruct(FieldRvaColumn, type, null) = .{
        .rva = IntData(4),
        .field = IndexData(.{ .table = .field }),
    };
};

pub const AssemblyColumn = enum {
    hash_alg_id,
    versions,
    flags,
    public_key,
    name,
    culture,

    const properties: std.enums.EnumFieldStruct(AssemblyColumn, type, null) = .{
        .hash_alg_id = IntData(4),
        .versions = IntData(8),
        .flags = IntData(4),
        .public_key = IndexData(.{ .heap = .blob }),
        .name = IndexData(.{ .heap = .string }),
        .culture = IndexData(.{ .heap = .string }),
    };
};

pub const AssemblyProcessorColumn = enum {
    processor,

    const properties: std.enums.EnumFieldStruct(AssemblyProcessorColumn, type, null) = .{
        .processor = IntData(4),
    };
};

pub const AssemblyOsColumn = enum {
    os_platform_id,
    os_major_version,
    os_minor_version,

    const properties: std.enums.EnumFieldStruct(AssemblyOsColumn, type, null) = .{
        .os_platform_id = IntData(4),
        .os_major_version = IntData(4),
        .os_minor_version = IntData(4),
    };
};

pub const AssemblyRefColumn = enum {
    versions,
    flags,
    public_key_or_token,
    name,
    culture,
    hash_value,

    const properties: std.enums.EnumFieldStruct(AssemblyRefColumn, type, null) = .{
        .versions = IntData(8),
        .flags = IntData(4),
        .public_key_or_token = IndexData(.{ .heap = .blob }),
        .name = IndexData(.{ .heap = .string }),
        .culture = IndexData(.{ .heap = .string }),
        .hash_value = IndexData(.{ .heap = .blob }),
    };
};

pub const AssemblyRefProcessorColumn = enum {
    processor,
    assembly_ref,

    const properties: std.enums.EnumFieldStruct(AssemblyRefProcessorColumn, type, null) = .{
        .processor = IntData(4),
        .assembly_ref = IndexData(.{ .table = .assembly_ref }),
    };
};

pub const AssemblyRefOsColumn = enum {
    os_platform_id,
    os_major_version,
    os_minor_version,
    assembly_ref,

    const properties: std.enums.EnumFieldStruct(AssemblyRefOsColumn, type, null) = .{
        .os_platform_id = IntData(4),
        .os_major_version = IntData(4),
        .os_minor_version = IntData(4),
        .assembly_ref = IndexData(.{ .table = .assembly_ref }),
    };
};

pub const FileColumn = enum {
    flags,
    name,
    hash_value,

    const properties: std.enums.EnumFieldStruct(FileColumn, type, null) = .{
        .flags = IntData(4),
        .name = IndexData(.{ .heap = .string }),
        .hash_value = IndexData(.{ .heap = .blob }),
    };
};

pub const ExportedTypeColumn = enum {
    flags,
    type_def_id,
    type_name,
    type_namespace,
    implementation,

    const properties: std.enums.EnumFieldStruct(ExportedTypeColumn, type, null) = .{
        .flags = IntData(4),
        .type_def_id = IntData(4),
        .type_name = IndexData(.{ .heap = .string }),
        .type_namespace = IndexData(.{ .heap = .string }),
        .implementation = CodedIndexData(.implementation),
    };
};

pub const ManifestResourceColumn = enum {
    offset,
    flags,
    name,
    implementation,

    const properties: std.enums.EnumFieldStruct(ManifestResourceColumn, type, null) = .{
        .offset = IntData(4),
        .flags = IntData(4),
        .name = IndexData(.{ .heap = .string }),
        .implementation = CodedIndexData(.implementation),
    };
};

pub const NestedClassColumn = enum {
    nested_class,
    enclosing_class,

    const properties: std.enums.EnumFieldStruct(NestedClassColumn, type, null) = .{
        .nested_class = IndexData(.{ .table = .type_def }),
        .enclosing_class = IndexData(.{ .table = .type_def }),
    };
};

pub const GenericParamColumn = enum {
    number,
    flags,
    owner,
    name,

    const properties: std.enums.EnumFieldStruct(GenericParamColumn, type, null) = .{
        .number = IntData(2),
        .flags = IntData(2),
        .owner = CodedIndexData(.type_or_method_def),
        .name = IndexData(.{ .heap = .string }),
    };
};

pub const MethodSpecColumn = enum {
    method,
    instantiation,

    const properties: std.enums.EnumFieldStruct(MethodSpecColumn, type, null) = .{
        .method = CodedIndexData(.method_def_or_ref),
        .instantiation = IndexData(.{ .heap = .blob }),
    };
};

pub const GenericParamConstraintColumn = enum {
    owner,
    constraint,

    const properties: std.enums.EnumFieldStruct(GenericParamConstraintColumn, type, null) = .{
        .owner = IndexData(.{ .table = .generic_param }),
        .constraint = CodedIndexData(.type_def_or_ref),
    };
};

pub const CodedIndex = enum {
    type_def_or_ref,
    has_constant,
    has_custom_attribute,
    has_field_marshal,
    has_decl_security,
    member_ref_parent,
    has_semantics,
    method_def_or_ref,
    member_forwarded,
    implementation,
    custom_attribute_type,
    resolution_scope,
    type_or_method_def,

    const properties: std.enums.EnumFieldStruct(CodedIndex, struct {
        u16,
        std.enums.EnumFieldStruct(Table, ?u5, @as(?u5, null)),
    }, null) = .{
        .type_def_or_ref = .{ 2, .{
            .type_def = 0,
            .type_ref = 1,
            .type_spec = 2,
        } },
        .has_constant = .{ 2, .{
            .field = 0,
            .param = 1,
            .property = 2,
        } },
        .has_custom_attribute = .{ 5, .{
            .method_def = 0,
            .field = 1,
            .type_ref = 2,
            .type_def = 3,
            .param = 4,
            .interface_impl = 5,
            .member_ref = 6,
            .module = 7,
            .property = 9,
            .event = 10,
            .stand_alone_sig = 11,
            .module_ref = 12,
            .type_spec = 13,
            .assembly = 14,
            .assembly_ref = 15,
            .file = 16,
            .exported_type = 17,
            .manifest_resource = 18,
            .generic_param = 19,
            .generic_param_constraint = 20,
            .method_spec = 21,
        } },
        .has_field_marshal = .{ 1, .{
            .field = 0,
            .param = 1,
        } },
        .has_decl_security = .{ 2, .{
            .type_def = 0,
            .method_def = 1,
            .assembly = 2,
        } },
        .member_ref_parent = .{ 3, .{
            .type_def = 0,
            .type_ref = 1,
            .module_ref = 2,
            .method_def = 3,
            .type_spec = 4,
        } },
        .has_semantics = .{ 1, .{
            .event = 0,
            .property = 1,
        } },
        .method_def_or_ref = .{ 1, .{
            .method_def = 0,
            .member_ref = 1,
        } },
        .member_forwarded = .{ 1, .{
            .field = 0,
            .method_def = 1,
        } },
        .implementation = .{ 2, .{
            .file = 0,
            .assembly_ref = 1,
            .exported_type = 2,
        } },
        .custom_attribute_type = .{ 3, .{
            .method_def = 2,
            .member_ref = 3,
        } },
        .resolution_scope = .{ 2, .{
            .module = 0,
            .module_ref = 1,
            .assembly_ref = 2,
            .type_ref = 3,
        } },
        .type_or_method_def = .{ 1, .{
            .type_def = 0,
            .method_def = 1,
        } },
    };

    pub fn tagBits(comptime index: CodedIndex) u16 {
        return @field(properties, @tagName(index))[0];
    }

    pub fn tagValues(comptime index: CodedIndex) std.enums.EnumFieldStruct(Table, ?u5, @as(?u5, null)) {
        return @field(properties, @tagName(index))[1];
    }

    pub fn tables(comptime index: CodedIndex) []const Table {
        const tag_values = comptime index.tagValues();
        comptime var result: []const Table = &.{};

        inline for (std.meta.tags(Table)) |table| {
            @setEvalBranchQuota(4000);

            if (@field(tag_values, @tagName(table))) |_| {
                result = result ++ .{table};
            }
        }

        return result;
    }

    pub fn Tag(comptime index: CodedIndex) type {
        const Int = @Type(.{ .int = .{
            .signedness = .unsigned,
            .bits = index.tagBits(),
        } });

        const tag_values = index.tagValues();
        var tag_fields: []const std.builtin.Type.EnumField = &.{};

        for (std.meta.tags(Table)) |table| {
            if (@field(tag_values, @tagName(table))) |tag_value| {
                tag_fields = tag_fields ++ .{std.builtin.Type.EnumField{
                    .name = @tagName(table),
                    .value = tag_value,
                }};
            }
        }

        return @Type(.{ .@"enum" = .{
            .tag_type = Int,
            .fields = tag_fields,
            .decls = &.{},
            .is_exhaustive = true,
        } });
    }
};

pub const IndexSize = enum {
    small,
    large,

    pub fn calcFromRowCounts(tag_bits: u16, row_counts: []const u32) IndexSize {
        for (row_counts) |row_count| if (row_count >= (@as(u32, 1) << @intCast(16 - tag_bits))) return .large;
        return .small;
    }
};

pub const IndexSizes = struct {
    heap: std.enums.EnumFieldStruct(Heap, IndexSize, null),
    table: std.enums.EnumFieldStruct(Table, IndexSize, null),
    coded: std.enums.EnumFieldStruct(CodedIndex, IndexSize, null),
};

pub fn IntData(bytes: u16) type {
    return struct {
        const Type = @Type(.{ .int = .{
            .signedness = .unsigned,
            .bits = 8 * bytes,
        } });

        pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexSizes) !Type {
            _ = sizes;
            return try stream.reader().readInt(Type, .little);
        }
    };
}

pub fn IndexData(target: union(enum) {
    heap: Heap,
    table: Table,
    coded: CodedIndex,
}) type {
    return struct {
        const Type = u32;

        pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexSizes) !Type {
            const size = switch (target) {
                .heap => |heap| @field(sizes.heap, @tagName(heap)),
                .table => |table| @field(sizes.table, @tagName(table)),
                .coded => |index| @field(sizes.coded, @tagName(index)),
            };

            return switch (size) {
                .small => try IntData(2).read(stream, sizes),
                .large => try IntData(4).read(stream, sizes),
            };
        }
    };
}

pub fn CodedIndexData(target: CodedIndex) type {
    return struct {
        const Type = struct {
            table: target.Tag(),
            index: u32,
        };

        pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexSizes) !Type {
            const raw_value = try IndexData(.{ .coded = target }).read(stream, sizes);
            var tag_mask: u32 = 0;
            for (0..target.tagBits()) |i| tag_mask |= @as(u32, 1) << @intCast(i);
            const table = try std.meta.intToEnum(target.Tag(), raw_value & tag_mask);
            const index = raw_value >> @intCast(target.tagBits());

            return .{
                .table = table,
                .index = index,
            };
        }
    };
}

pub const TableStream = struct {
    reserved0: u32,
    major_version: u8,
    minor_version: u8,
    heap_sizes: u8,
    reserved1: u8,
    valid: u64,
    sorted: u64,
    rows: std.ArrayList(u32),
    tables: Tables,

    pub fn read(allocator: std.mem.Allocator, bytes: []const u8) !TableStream {
        var stream = std.io.fixedBufferStream(bytes);
        const reader = stream.reader();

        const raw_table_stream_0 = try reader.readStructEndian(extern struct {
            Reserved0: u32,
            MajorVersion: u8,
            MinorVersion: u8,
            HeapSizes: u8,
            Reserved1: u8,
            Valid: u64,
            Sorted: u64,
        }, .little);

        var valid_vector = raw_table_stream_0.Valid;
        var rows = try std.ArrayList(u32).initCapacity(allocator, @popCount(raw_table_stream_0.Valid));
        errdefer rows.deinit();
        var row_counts: std.enums.EnumFieldStruct(Table, u32, 0) = .{};

        inline for (comptime std.meta.tags(Table)) |table| {
            const valid_bit = table.validBit();

            if (valid_vector & valid_bit != 0) {
                valid_vector &= ~valid_bit;
                const table_row_count = try reader.readInt(u32, .little);
                rows.appendAssumeCapacity(table_row_count);
                @field(row_counts, @tagName(table)) = table_row_count;
            }
        }

        if (valid_vector != 0) return error.PeInvalidTableValidVector;
        var index_sizes: IndexSizes = undefined;

        inline for (comptime std.meta.tags(Heap)) |heap| {
            @field(index_sizes.heap, @tagName(heap)) = switch (heap.flagBit() & raw_table_stream_0.HeapSizes) {
                0 => .small,
                else => .large,
            };
        }

        inline for (comptime std.meta.tags(Table)) |table| {
            @field(index_sizes.table, @tagName(table)) = .calcFromRowCounts(0, &.{@field(row_counts, @tagName(table))});
        }

        inline for (comptime std.meta.tags(CodedIndex)) |index| {
            const tag_bits = index.tagBits();
            const coded_tables = comptime index.tables();
            var coded_row_counts: [coded_tables.len]u32 = undefined;

            inline for (&coded_row_counts, coded_tables) |*coded_row_count, coded_table| {
                coded_row_count.* = @field(row_counts, @tagName(coded_table));
            }

            @field(index_sizes.coded, @tagName(index)) = .calcFromRowCounts(tag_bits, &coded_row_counts);
        }

        var initialized_tables = std.enums.EnumSet(Table).initEmpty();
        var tables: Tables = undefined;

        errdefer {
            @setEvalBranchQuota(10000);

            inline for (comptime std.meta.tags(Table)) |table| {
                if (initialized_tables.contains(table)) {
                    @field(tables, @tagName(table)).deinit();
                }
            }
        }

        inline for (comptime std.meta.tags(Table)) |table| {
            const row_count = @field(row_counts, @tagName(table));
            var table_rows = try std.ArrayList(table.Row()).initCapacity(allocator, row_count);
            errdefer table_rows.deinit();
            for (0..row_count) |_| table_rows.appendAssumeCapacity(try table.readRow(&stream, index_sizes));
            @field(tables, @tagName(table)) = table_rows;
            initialized_tables.insert(table);
        }

        return .{
            .reserved0 = raw_table_stream_0.Reserved0,
            .major_version = raw_table_stream_0.MajorVersion,
            .minor_version = raw_table_stream_0.MinorVersion,
            .heap_sizes = raw_table_stream_0.HeapSizes,
            .reserved1 = raw_table_stream_0.Reserved1,
            .valid = raw_table_stream_0.Valid,
            .sorted = raw_table_stream_0.Sorted,
            .rows = rows,
            .tables = tables,
        };
    }

    pub fn free(stream: TableStream) void {
        stream.rows.deinit();

        inline for (comptime std.meta.fieldNames(Tables)) |field_name| {
            @field(stream.tables, field_name).deinit();
        }
    }
};

pub const Tables = blk: {
    const table_tags = std.meta.tags(Table);
    var tables_fields: [table_tags.len]std.builtin.Type.StructField = undefined;

    for (&tables_fields, table_tags) |*tables_field, table_tag| {
        const Type = std.ArrayList(table_tag.Row());

        tables_field.* = .{
            .name = @tagName(table_tag),
            .type = Type,
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(Type),
        };
    }

    break :blk @Type(.{ .@"struct" = .{
        .layout = .auto,
        .fields = &tables_fields,
        .decls = &.{},
        .is_tuple = false,
    } });
};
