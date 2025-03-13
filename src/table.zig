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

    pub fn readRow(comptime table: Table, stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !table.Row() {
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
        .name = HeapIndexData(.string),
        .mvid = HeapIndexData(.guid),
        .enc_id = HeapIndexData(.guid),
        .enc_base_id = HeapIndexData(.guid),
    };
};

pub const TypeRefColumn = enum {
    resolution_scope,
    type_name,
    type_namespace,

    const properties: std.enums.EnumFieldStruct(TypeRefColumn, type, null) = .{
        .resolution_scope = CodedIndexData(.resolution_scope),
        .type_name = HeapIndexData(.string),
        .type_namespace = HeapIndexData(.string),
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
        .flags = TypeAttributes,
        .type_name = HeapIndexData(.string),
        .type_namespace = HeapIndexData(.string),
        .extends = CodedIndexData(.type_def_or_ref),
        .field_list = TableIndexData(.field),
        .method_list = TableIndexData(.method_def),
    };
};

pub const FieldColumn = enum {
    flags,
    name,
    signature,

    const properties: std.enums.EnumFieldStruct(FieldColumn, type, null) = .{
        .flags = FieldAttributes,
        .name = HeapIndexData(.string),
        .signature = HeapIndexData(.blob),
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
        .impl_flags = MethodImplAttributes,
        .flags = MethodAttributes,
        .name = HeapIndexData(.string),
        .signature = HeapIndexData(.blob),
        .param_list = TableIndexData(.param),
    };
};

pub const ParamColumn = enum {
    flags,
    sequence,
    name,

    const properties: std.enums.EnumFieldStruct(ParamColumn, type, null) = .{
        .flags = ParameterAttributes,
        .sequence = IntData(2),
        .name = HeapIndexData(.string),
    };
};

pub const InterfaceImplColumn = enum {
    class,
    interface,

    const properties: std.enums.EnumFieldStruct(InterfaceImplColumn, type, null) = .{
        .class = TableIndexData(.type_def),
        .interface = CodedIndexData(.type_def_or_ref),
    };
};

pub const MemberRefColumn = enum {
    class,
    name,
    signature,

    const properties: std.enums.EnumFieldStruct(MemberRefColumn, type, null) = .{
        .class = CodedIndexData(.member_ref_parent),
        .name = HeapIndexData(.string),
        .signature = HeapIndexData(.blob),
    };
};

pub const ConstantColumn = enum {
    type,
    parent,
    value,

    const properties: std.enums.EnumFieldStruct(ConstantColumn, type, null) = .{
        .type = IntData(2),
        .parent = CodedIndexData(.has_constant),
        .value = HeapIndexData(.blob),
    };
};

pub const CustomAttributeColumn = enum {
    parent,
    type,
    value,

    const properties: std.enums.EnumFieldStruct(CustomAttributeColumn, type, null) = .{
        .parent = CodedIndexData(.has_custom_attribute),
        .type = CodedIndexData(.custom_attribute_type),
        .value = HeapIndexData(.blob),
    };
};

pub const FieldMarshalColumn = enum {
    parent,
    native_type,

    const properties: std.enums.EnumFieldStruct(FieldMarshalColumn, type, null) = .{
        .parent = CodedIndexData(.has_field_marshal),
        .native_type = HeapIndexData(.blob),
    };
};

pub const DeclSecurityColumn = enum {
    action,
    parent,
    permission_set,

    const properties: std.enums.EnumFieldStruct(DeclSecurityColumn, type, null) = .{
        .action = IntData(2),
        .parent = CodedIndexData(.has_decl_security),
        .permission_set = HeapIndexData(.blob),
    };
};

pub const ClassLayoutColumn = enum {
    packing_size,
    class_size,
    parent,

    const properties: std.enums.EnumFieldStruct(ClassLayoutColumn, type, null) = .{
        .packing_size = IntData(2),
        .class_size = IntData(4),
        .parent = TableIndexData(.type_def),
    };
};

pub const FieldLayoutColumn = enum {
    offset,
    field,

    const properties: std.enums.EnumFieldStruct(FieldLayoutColumn, type, null) = .{
        .offset = IntData(4),
        .field = TableIndexData(.field),
    };
};

pub const StandAloneSigColumn = enum {
    signature,

    const properties: std.enums.EnumFieldStruct(StandAloneSigColumn, type, null) = .{
        .signature = HeapIndexData(.blob),
    };
};

pub const EventMapColumn = enum {
    parent,
    event_list,

    const properties: std.enums.EnumFieldStruct(EventMapColumn, type, null) = .{
        .parent = TableIndexData(.type_def),
        .event_list = TableIndexData(.event),
    };
};

pub const EventColumn = enum {
    event_flags,
    name,
    event_type,

    const properties: std.enums.EnumFieldStruct(EventColumn, type, null) = .{
        .event_flags = EventAttributes,
        .name = HeapIndexData(.string),
        .event_type = CodedIndexData(.type_def_or_ref),
    };
};

pub const PropertyMapColumn = enum {
    parent,
    property_list,

    const properties: std.enums.EnumFieldStruct(PropertyMapColumn, type, null) = .{
        .parent = TableIndexData(.type_def),
        .property_list = TableIndexData(.property),
    };
};

pub const PropertyColumn = enum {
    flags,
    name,
    type,

    const properties: std.enums.EnumFieldStruct(PropertyColumn, type, null) = .{
        .flags = PropertyAttributes,
        .name = HeapIndexData(.string),
        .type = HeapIndexData(.blob),
    };
};

pub const MethodSemanticsColumn = enum {
    semantics,
    method,
    association,

    const properties: std.enums.EnumFieldStruct(MethodSemanticsColumn, type, null) = .{
        .semantics = MethodSemanticsAttributes,
        .method = TableIndexData(.method_def),
        .association = CodedIndexData(.has_semantics),
    };
};

pub const MethodImplColumn = enum {
    class,
    method_body,
    method_declaration,

    const properties: std.enums.EnumFieldStruct(MethodImplColumn, type, null) = .{
        .class = TableIndexData(.type_def),
        .method_body = CodedIndexData(.method_def_or_ref),
        .method_declaration = CodedIndexData(.method_def_or_ref),
    };
};

pub const ModuleRefColumn = enum {
    name,

    const properties: std.enums.EnumFieldStruct(ModuleRefColumn, type, null) = .{
        .name = HeapIndexData(.string),
    };
};

pub const TypeSpecColumn = enum {
    signature,

    const properties: std.enums.EnumFieldStruct(TypeSpecColumn, type, null) = .{
        .signature = HeapIndexData(.blob),
    };
};

pub const ImplMapColumn = enum {
    mapping_flags,
    member_forwarded,
    import_name,
    import_scope,

    const properties: std.enums.EnumFieldStruct(ImplMapColumn, type, null) = .{
        .mapping_flags = PInvokeAttributes,
        .member_forwarded = CodedIndexData(.member_forwarded),
        .import_name = HeapIndexData(.string),
        .import_scope = TableIndexData(.module_ref),
    };
};

pub const FieldRvaColumn = enum {
    rva,
    field,

    const properties: std.enums.EnumFieldStruct(FieldRvaColumn, type, null) = .{
        .rva = IntData(4),
        .field = TableIndexData(.field),
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
        .hash_alg_id = AssemblyHashAlgorithm,
        .versions = VersionsData,
        .flags = AssemblyFlags,
        .public_key = HeapIndexData(.blob),
        .name = HeapIndexData(.string),
        .culture = HeapIndexData(.string),
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
        .versions = VersionsData,
        .flags = AssemblyFlags,
        .public_key_or_token = HeapIndexData(.blob),
        .name = HeapIndexData(.string),
        .culture = HeapIndexData(.string),
        .hash_value = HeapIndexData(.blob),
    };
};

pub const AssemblyRefProcessorColumn = enum {
    processor,
    assembly_ref,

    const properties: std.enums.EnumFieldStruct(AssemblyRefProcessorColumn, type, null) = .{
        .processor = IntData(4),
        .assembly_ref = TableIndexData(.assembly_ref),
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
        .assembly_ref = TableIndexData(.assembly_ref),
    };
};

pub const FileColumn = enum {
    flags,
    name,
    hash_value,

    const properties: std.enums.EnumFieldStruct(FileColumn, type, null) = .{
        .flags = FileAttributes,
        .name = HeapIndexData(.string),
        .hash_value = HeapIndexData(.blob),
    };
};

pub const ExportedTypeColumn = enum {
    flags,
    type_def_id,
    type_name,
    type_namespace,
    implementation,

    const properties: std.enums.EnumFieldStruct(ExportedTypeColumn, type, null) = .{
        .flags = TypeAttributes,
        .type_def_id = IntData(4),
        .type_name = HeapIndexData(.string),
        .type_namespace = HeapIndexData(.string),
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
        .flags = ManifestResourceAttributes,
        .name = HeapIndexData(.string),
        .implementation = CodedIndexData(.implementation),
    };
};

pub const NestedClassColumn = enum {
    nested_class,
    enclosing_class,

    const properties: std.enums.EnumFieldStruct(NestedClassColumn, type, null) = .{
        .nested_class = TableIndexData(.type_def),
        .enclosing_class = TableIndexData(.type_def),
    };
};

pub const GenericParamColumn = enum {
    number,
    flags,
    owner,
    name,

    const properties: std.enums.EnumFieldStruct(GenericParamColumn, type, null) = .{
        .number = IntData(2),
        .flags = GenericParameterAttributes,
        .owner = CodedIndexData(.type_or_method_def),
        .name = HeapIndexData(.string),
    };
};

pub const MethodSpecColumn = enum {
    method,
    instantiation,

    const properties: std.enums.EnumFieldStruct(MethodSpecColumn, type, null) = .{
        .method = CodedIndexData(.method_def_or_ref),
        .instantiation = HeapIndexData(.blob),
    };
};

pub const GenericParamConstraintColumn = enum {
    owner,
    constraint,

    const properties: std.enums.EnumFieldStruct(GenericParamConstraintColumn, type, null) = .{
        .owner = TableIndexData(.generic_param),
        .constraint = CodedIndexData(.type_def_or_ref),
    };
};

pub const CodedIndexKind = enum {
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

    const properties: std.enums.EnumFieldStruct(CodedIndexKind, struct {
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

    pub fn tagBits(comptime index: CodedIndexKind) u16 {
        return @field(properties, @tagName(index))[0];
    }

    pub fn tagValues(comptime index: CodedIndexKind) std.enums.EnumFieldStruct(Table, ?u5, @as(?u5, null)) {
        return @field(properties, @tagName(index))[1];
    }

    pub fn tables(comptime index: CodedIndexKind) []const Table {
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

    pub fn Tag(comptime index: CodedIndexKind) type {
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

pub const IndexKind = union(enum) {
    heap: Heap,
    table: Table,
    coded: CodedIndexKind,
};

pub fn IndexMap(T: type) type {
    return struct {
        heap: std.enums.EnumFieldStruct(Heap, T, null),
        table: std.enums.EnumFieldStruct(Table, T, null),
        coded: std.enums.EnumFieldStruct(CodedIndexKind, T, null),

        pub fn get(map: IndexMap(T), comptime index: IndexKind) T {
            return switch (index) {
                .heap => |heap| @field(map.heap, @tagName(heap)),
                .table => |table| @field(map.table, @tagName(table)),
                .coded => |coded_index| @field(map.coded, @tagName(coded_index)),
            };
        }
    };
}

pub const IndexSize = enum {
    small,
    large,

    pub fn calcFromRowCounts(tag_bits: u16, row_counts: []const u32) IndexSize {
        for (row_counts) |row_count| if (row_count >= (@as(u32, 1) << @intCast(16 - tag_bits))) return .large;
        return .small;
    }
};

pub fn IntData(bytes: u16) type {
    return struct {
        pub const Type = @Type(.{ .int = .{
            .signedness = .unsigned,
            .bits = 8 * bytes,
        } });

        pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
            _ = sizes;
            return try stream.reader().readInt(Type, .little);
        }
    };
}

pub fn IndexData(index: IndexKind) type {
    return struct {
        pub const Type = u32;

        pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
            return switch (sizes.get(index)) {
                .small => try IntData(2).read(stream, sizes),
                .large => try IntData(4).read(stream, sizes),
            };
        }
    };
}

pub fn SimpleIndexData(index: IndexKind) type {
    return struct {
        pub const Type = ?u32;

        pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
            const optional_index = try IndexData(index).read(stream, sizes);

            return switch (optional_index) {
                0 => null,
                else => optional_index - 1,
            };
        }
    };
}

pub fn HeapIndexData(heap: Heap) type {
    return struct {
        pub const Type = ?u32;

        pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
            return try SimpleIndexData(.{ .heap = heap }).read(stream, sizes);
        }
    };
}

pub fn TableIndexData(table: Table) type {
    return struct {
        pub const Type = ?u32;

        pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
            return try SimpleIndexData(.{ .table = table }).read(stream, sizes);
        }
    };
}

pub fn CodedIndexData(target: CodedIndexKind) type {
    return struct {
        pub const Type = struct {
            table: target.Tag(),
            index: ?u32,
        };

        pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
            const raw_value = try IndexData(.{ .coded = target }).read(stream, sizes);
            var tag_mask: u32 = 0;
            for (0..target.tagBits()) |i| tag_mask |= @as(u32, 1) << @intCast(i);
            const table = try std.meta.intToEnum(target.Tag(), raw_value & tag_mask);
            const optional_index = raw_value >> @intCast(target.tagBits());

            const index = switch (optional_index) {
                0 => null,
                else => optional_index - 1,
            };

            return .{
                .table = table,
                .index = index,
            };
        }
    };
}

pub const VersionsData = struct {
    pub const Type = struct {
        major_version: u16,
        minor_version: u16,
        build_number: u16,
        revision_number: u16,
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        return .{
            .major_version = try IntData(2).read(stream, sizes),
            .minor_version = try IntData(2).read(stream, sizes),
            .build_number = try IntData(2).read(stream, sizes),
            .revision_number = try IntData(2).read(stream, sizes),
        };
    }
};

pub fn PackedData(T: type) type {
    return struct {
        pub const Type = T;

        pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
            const t_info = @typeInfo(T).@"struct";
            const Int = t_info.backing_integer.?;
            const t_fields = t_info.fields;
            comptime var u_fields: [t_fields.len]std.builtin.Type.StructField = undefined;

            inline for (&u_fields, t_fields) |*u_field, t_field| {
                u_field.* = .{
                    .name = t_field.name,
                    .type = @typeInfo(t_field.type).@"enum".tag_type,
                    .default_value_ptr = null,
                    .is_comptime = false,
                    .alignment = t_field.alignment,
                };
            }

            const u_info: std.builtin.Type = comptime .{ .@"struct" = .{
                .layout = .@"packed",
                .backing_integer = Int,
                .fields = &u_fields,
                .decls = &.{},
                .is_tuple = false,
            } };

            const U = @Type(u_info);
            const int_value = try IntData(@typeInfo(Int).int.bits / 8).read(stream, sizes);
            const u_value: U = @bitCast(int_value);
            var t_value: T = undefined;

            inline for (t_fields) |t_field| {
                @field(t_value, t_field.name) = try std.meta.intToEnum(t_field.type, @field(u_value, t_field.name));
            }

            return t_value;
        }
    };
}

pub fn PackedPadding(Int: type) type {
    return enum(Int) {
        padding = 0,
    };
}

pub fn PackedBool(Int: type) type {
    return enum(Int) {
        false = 0,
        true = 1,

        pub fn toBool(packed_bool: PackedBool(Int)) bool {
            return switch (packed_bool) {
                .false => false,
                .true => true,
            };
        }
    };
}

pub fn PackedInt(Int: type) type {
    return enum(Int) {
        _,

        pub fn toInt(packed_int: PackedInt(Int)) Int {
            return @intFromEnum(packed_int);
        }
    };
}

pub const AssemblyHashAlgorithm = struct {
    pub const Type = enum {
        none,
        md5,
        sha1,
        sha256,
        sha384,
        sha512,
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        const raw_value = try PackedData(packed struct(u32) {
            value: enum(u32) {
                None = 0,
                MD5 = 32771,
                Sha1 = 32772,
                Sha256 = 32780,
                Sha384 = 32781,
                Sha512 = 32782,
            },
        }).read(stream, sizes);

        return switch (raw_value.value) {
            .None => .none,
            .MD5 => .md5,
            .Sha1 => .sha1,
            .Sha256 => .sha256,
            .Sha384 => .sha384,
            .Sha512 => .sha512,
        };
    }
};

pub const AssemblyFlags = struct {
    pub const Type = struct {
        public_key: bool,
        retargetable: bool,
        content_type: enum {
            default,
            windows_runtime,
        },
        disable_jit_compile_optimizer: bool,
        enable_jit_compile_tracking: bool,
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        const raw_value = try PackedData(packed struct(u32) {
            PublicKey: PackedBool(u1),
            padding0: PackedPadding(u7),
            Retargetable: PackedBool(u1),
            ContentType: enum(u3) {
                Default = 0,
                WindowsRuntime = 1,
            },
            padding1: PackedPadding(u2),
            DisableJitCompileOptimizer: PackedBool(u1),
            EnableJitCompileTracking: PackedBool(u1),
            padding2: PackedPadding(u16),
        }).read(stream, sizes);

        return .{
            .public_key = raw_value.PublicKey.toBool(),
            .retargetable = raw_value.Retargetable.toBool(),
            .content_type = switch (raw_value.ContentType) {
                .Default => .default,
                .WindowsRuntime => .windows_runtime,
            },
            .disable_jit_compile_optimizer = raw_value.DisableJitCompileOptimizer.toBool(),
            .enable_jit_compile_tracking = raw_value.EnableJitCompileTracking.toBool(),
        };
    }
};

pub const EventAttributes = struct {
    pub const Type = struct {
        special_name: bool,
        rt_special_name: bool,
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        const raw_value = try PackedData(packed struct(u16) {
            padding0: PackedPadding(u9),
            SpecialName: PackedBool(u1),
            RTSpecialName: PackedBool(u1),
            padding1: PackedPadding(u5),
        }).read(stream, sizes);

        return .{
            .special_name = switch (raw_value.SpecialName) {
                .false => false,
                .true => true,
            },
            .rt_special_name = switch (raw_value.RTSpecialName) {
                .false => false,
                .true => true,
            },
        };
    }
};

pub const FieldAttributes = struct {
    pub const Type = struct {
        field_access: enum {
            private_scope,
            private,
            fam_and_assem,
            assembly,
            family,
            fam_or_assem,
            public,
        },
        static: bool,
        init_only: bool,
        literal: bool,
        not_serialized: bool,
        has_field_rva: bool,
        special_name: bool,
        rt_special_name: bool,
        has_field_marshal: bool,
        pinvoke_impl: bool,
        has_default: bool,
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        const raw_value = try PackedData(packed struct(u16) {
            FieldAccess: enum(u3) {
                PrivateScope = 0,
                Private = 1,
                FamANDAssem = 2,
                Assembly = 3,
                Family = 4,
                FamORAssem = 5,
                Public = 6,
            },
            padding0: PackedPadding(u1),
            Static: PackedBool(u1),
            InitOnly: PackedBool(u1),
            Literal: PackedBool(u1),
            NotSerialized: PackedBool(u1),
            HasFieldRVA: PackedBool(u1),
            SpecialName: PackedBool(u1),
            RTSpecialName: PackedBool(u1),
            padding1: PackedPadding(u1),
            HasFieldMarshal: PackedBool(u1),
            PinvokeImpl: PackedBool(u1),
            padding2: PackedPadding(u1),
            HasDefault: PackedBool(u1),
        }).read(stream, sizes);

        return .{
            .field_access = switch (raw_value.FieldAccess) {
                .PrivateScope => .private_scope,
                .Private => .private,
                .FamANDAssem => .fam_and_assem,
                .Assembly => .assembly,
                .Family => .family,
                .FamORAssem => .fam_or_assem,
                .Public => .public,
            },
            .static = raw_value.Static.toBool(),
            .init_only = raw_value.InitOnly.toBool(),
            .literal = raw_value.Literal.toBool(),
            .not_serialized = raw_value.NotSerialized.toBool(),
            .has_field_rva = raw_value.HasFieldRVA.toBool(),
            .special_name = raw_value.SpecialName.toBool(),
            .rt_special_name = raw_value.RTSpecialName.toBool(),
            .has_field_marshal = raw_value.HasFieldMarshal.toBool(),
            .pinvoke_impl = raw_value.PinvokeImpl.toBool(),
            .has_default = raw_value.HasDefault.toBool(),
        };
    }
};

pub const FileAttributes = struct {
    pub const Type = enum {
        contains_meta_data,
        contains_no_meta_data,
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        const raw_value = try PackedData(packed struct(u32) {
            value: enum(u32) {
                ContainsMetaData = 0,
                ContainsNoMetaData = 1,
            },
        }).read(stream, sizes);

        return switch (raw_value.value) {
            .ContainsMetaData => .contains_meta_data,
            .ContainsNoMetaData => .contains_no_meta_data,
        };
    }
};

pub const GenericParameterAttributes = struct {
    pub const Type = struct {
        variance: enum {
            none,
            covariant,
            contravariant,
        },
        special_constraint: enum {
            reference_type_constraint,
            not_nullable_value_type_constraint,
            default_constructor_constraint,
        },
        allow_by_ref_like: bool,
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        const raw_value = try PackedData(packed struct(u16) {
            Variance: enum(u3) {
                None = 0,
                Covariant = 1,
                Contravariant = 2,
            },
            SpecialConstraint: enum(u3) {
                ReferenceTypeConstraint = 1,
                NotNullableValueTypeConstraint = 2,
                DefaultConstructorConstraint = 4,
            },
            AllowByRefLike: PackedBool(u1),
            padding0: PackedPadding(u9),
        }).read(stream, sizes);

        return .{
            .variance = switch (raw_value.Variance) {
                .None => .none,
                .Covariant => .covariant,
                .Contravariant => .contravariant,
            },
            .special_constraint = switch (raw_value.SpecialConstraint) {
                .ReferenceTypeConstraint => .reference_type_constraint,
                .NotNullableValueTypeConstraint => .not_nullable_value_type_constraint,
                .DefaultConstructorConstraint => .default_constructor_constraint,
            },
            .allow_by_ref_like = raw_value.AllowByRefLike.toBool(),
        };
    }
};

pub const PInvokeAttributes = struct {
    pub const Type = struct {
        no_mangle: bool,
        char_set: enum {
            char_set_not_spec,
            char_set_ansi,
            char_set_unicode,
            char_set_auto,
        },
        supports_last_error: bool,
        call_conv: enum {
            call_conv_platformapi,
            call_conv_cdecl,
            call_conv_stdcall,
            call_conv_thiscall,
            call_conv_fastcall,
        },
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        const raw_value = try PackedData(packed struct(u16) {
            NoMangle: PackedBool(u1),
            CharSet: enum(u2) {
                CharSetNotSpec = 0,
                CharSetAnsi = 1,
                CharSetUnicode = 2,
                CharSetAuto = 3,
            },
            padding0: PackedPadding(u3),
            SupportsLastError: PackedBool(u1),
            padding1: PackedPadding(u1),
            CallConv: enum(u3) {
                CallConvPlatformapi = 1,
                CallConvCdecl = 2,
                CallConvStdcall = 3,
                CallConvThiscall = 4,
                CallConvFastcall = 5,
            },
            padding2: PackedPadding(u5),
        }).read(stream, sizes);

        return .{
            .no_mangle = raw_value.NoMangle.toBool(),
            .char_set = switch (raw_value.CharSet) {
                .CharSetNotSpec => .char_set_not_spec,
                .CharSetAnsi => .char_set_ansi,
                .CharSetUnicode => .char_set_unicode,
                .CharSetAuto => .char_set_auto,
            },
            .supports_last_error = raw_value.SupportsLastError.toBool(),
            .call_conv = switch (raw_value.CallConv) {
                .CallConvPlatformapi => .call_conv_platformapi,
                .CallConvCdecl => .call_conv_cdecl,
                .CallConvStdcall => .call_conv_stdcall,
                .CallConvThiscall => .call_conv_thiscall,
                .CallConvFastcall => .call_conv_fastcall,
            },
        };
    }
};

pub const ManifestResourceAttributes = struct {
    pub const Type = struct {
        visibility: enum {
            public,
            private,
        },
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        const raw_value = try PackedData(packed struct(u32) {
            Visibility: enum(u3) {
                Public = 1,
                Private = 2,
            },
            padding0: PackedPadding(u29),
        }).read(stream, sizes);

        return .{
            .visibility = switch (raw_value.Visibility) {
                .Public => .public,
                .Private => .private,
            },
        };
    }
};

pub const MethodAttributes = struct {
    pub const Type = struct {
        member_access: enum {
            private_scope,
            private,
            fam_and_assem,
            assembly,
            family,
            fam_or_assem,
            public,
        },
        unmanaged_export: bool,
        static: bool,
        final: bool,
        virtual: bool,
        hide_by_sig: bool,
        vtable_layout: enum {
            reuse_slot,
            new_slot,
        },
        check_access_on_override: bool,
        abstract: bool,
        special_name: bool,
        rt_special_name: bool,
        pinvoke_impl: bool,
        has_security: bool,
        require_sec_object: bool,
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        const raw_value = try PackedData(packed struct(u16) {
            MemberAccess: enum(u3) {
                PrivateScope = 0,
                Private = 1,
                FamANDAssem = 2,
                Assembly = 3,
                Family = 4,
                FamORAssem = 5,
                Public = 6,
            },
            UnmanagedExport: PackedBool(u1),
            Static: PackedBool(u1),
            Final: PackedBool(u1),
            Virtual: PackedBool(u1),
            HideBySig: PackedBool(u1),
            VtableLayout: enum(u1) {
                ReuseSlot = 0,
                NewSlot = 1,
            },
            CheckAccessOnOverride: PackedBool(u1),
            Abstract: PackedBool(u1),
            SpecialName: PackedBool(u1),
            RTSpecialName: PackedBool(u1),
            PinvokeImpl: PackedBool(u1),
            HasSecurity: PackedBool(u1),
            RequireSecObject: PackedBool(u1),
        }).read(stream, sizes);

        return .{
            .member_access = switch (raw_value.MemberAccess) {
                .PrivateScope => .private_scope,
                .Private => .private,
                .FamANDAssem => .fam_and_assem,
                .Assembly => .assembly,
                .Family => .family,
                .FamORAssem => .fam_or_assem,
                .Public => .public,
            },
            .unmanaged_export = raw_value.UnmanagedExport.toBool(),
            .static = raw_value.Static.toBool(),
            .final = raw_value.Final.toBool(),
            .virtual = raw_value.Virtual.toBool(),
            .hide_by_sig = raw_value.HideBySig.toBool(),
            .vtable_layout = switch (raw_value.VtableLayout) {
                .ReuseSlot => .reuse_slot,
                .NewSlot => .new_slot,
            },
            .check_access_on_override = raw_value.CheckAccessOnOverride.toBool(),
            .abstract = raw_value.Abstract.toBool(),
            .special_name = raw_value.SpecialName.toBool(),
            .rt_special_name = raw_value.RTSpecialName.toBool(),
            .pinvoke_impl = raw_value.PinvokeImpl.toBool(),
            .has_security = raw_value.HasSecurity.toBool(),
            .require_sec_object = raw_value.RequireSecObject.toBool(),
        };
    }
};

pub const MethodImplAttributes = struct {
    pub const Type = struct {
        code_type: enum {
            il,
            native,
            optil,
            runtime,
        },
        managed: enum {
            managed,
            unmanaged,
        },
        no_inlining: bool,
        forward_ref: bool,
        synchronized: bool,
        no_optimization: bool,
        preserve_sig: bool,
        aggressive_inlining: bool,
        aggressive_optimization: bool,
        internal_call: bool,
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        const raw_value = try PackedData(packed struct(u16) {
            CodeType: enum(u2) {
                IL = 0,
                Native = 1,
                OPTIL = 2,
                Runtime = 3,
            },
            Managed: enum(u1) {
                Managed = 0,
                Unmanaged = 1,
            },
            NoInlining: PackedBool(u1),
            ForwardRef: PackedBool(u1),
            Synchronized: PackedBool(u1),
            NoOptimization: PackedBool(u1),
            PreserveSig: PackedBool(u1),
            AggressiveInlining: PackedBool(u1),
            AggressiveOptimization: PackedBool(u1),
            padding0: PackedPadding(u2),
            InternalCall: PackedBool(u1),
            padding1: PackedPadding(u3),
        }).read(stream, sizes);

        return .{
            .code_type = switch (raw_value.CodeType) {
                .IL => .il,
                .Native => .native,
                .OPTIL => .optil,
                .Runtime => .runtime,
            },
            .managed = switch (raw_value.Managed) {
                .Managed => .managed,
                .Unmanaged => .unmanaged,
            },
            .no_inlining = raw_value.NoInlining.toBool(),
            .forward_ref = raw_value.ForwardRef.toBool(),
            .synchronized = raw_value.Synchronized.toBool(),
            .no_optimization = raw_value.NoOptimization.toBool(),
            .preserve_sig = raw_value.PreserveSig.toBool(),
            .aggressive_inlining = raw_value.AggressiveInlining.toBool(),
            .aggressive_optimization = raw_value.AggressiveOptimization.toBool(),
            .internal_call = raw_value.InternalCall.toBool(),
        };
    }
};

pub const MethodSemanticsAttributes = struct {
    pub const Type = struct {
        setter: bool,
        getter: bool,
        other: bool,
        adder: bool,
        remover: bool,
        raiser: bool,
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        const raw_value = try PackedData(packed struct(u16) {
            Setter: PackedBool(u1),
            Getter: PackedBool(u1),
            Other: PackedBool(u1),
            Adder: PackedBool(u1),
            Remover: PackedBool(u1),
            Raiser: PackedBool(u1),
            padding0: PackedPadding(u10),
        }).read(stream, sizes);

        return .{
            .setter = raw_value.Setter.toBool(),
            .getter = raw_value.Getter.toBool(),
            .other = raw_value.Other.toBool(),
            .adder = raw_value.Adder.toBool(),
            .remover = raw_value.Remover.toBool(),
            .raiser = raw_value.Raiser.toBool(),
        };
    }
};

pub const ParameterAttributes = struct {
    pub const Type = struct {
        in: bool,
        out: bool,
        lcid: bool,
        retval: bool,
        optional: bool,
        has_default: bool,
        has_field_marshal: bool,
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        const raw_value = try PackedData(packed struct(u16) {
            In: PackedBool(u1),
            Out: PackedBool(u1),
            Lcid: PackedBool(u1),
            Retval: PackedBool(u1),
            Optional: PackedBool(u1),
            padding0: PackedPadding(u7),
            HasDefault: PackedBool(u1),
            HasFieldMarshal: PackedBool(u1),
            padding1: PackedPadding(u2),
        }).read(stream, sizes);

        return .{
            .in = raw_value.In.toBool(),
            .out = raw_value.Out.toBool(),
            .lcid = raw_value.Lcid.toBool(),
            .retval = raw_value.Retval.toBool(),
            .optional = raw_value.Optional.toBool(),
            .has_default = raw_value.HasDefault.toBool(),
            .has_field_marshal = raw_value.HasFieldMarshal.toBool(),
        };
    }
};

pub const PropertyAttributes = struct {
    pub const Type = struct {
        special_name: bool,
        rt_special_name: bool,
        has_default: bool,
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        const raw_value = try PackedData(packed struct(u16) {
            padding0: PackedPadding(u9),
            SpecialName: PackedBool(u1),
            RTSpecialName: PackedBool(u1),
            padding1: PackedPadding(u1),
            HasDefault: PackedBool(u1),
            padding2: PackedPadding(u3),
        }).read(stream, sizes);

        return .{
            .special_name = raw_value.SpecialName.toBool(),
            .rt_special_name = raw_value.RTSpecialName.toBool(),
            .has_default = raw_value.HasDefault.toBool(),
        };
    }
};

pub const TypeAttributes = struct {
    pub const Type = struct {
        visibility: enum {
            not_public,
            public,
            nested_public,
            nested_private,
            nested_family,
            nested_assembly,
            nested_fam_and_assem,
            nested_fam_or_assem,
        },
        layout: enum {
            auto_layout,
            sequential_layout,
            explicit_layout,
        },
        class_semantics: enum {
            class,
            interface,
        },
        abstract: bool,
        sealed: bool,
        special_name: bool,
        rt_special_name: bool,
        import: bool,
        serializable: bool,
        windows_runtime: bool,
        string_format: enum {
            ansi_class,
            unicode_class,
            auto_class,
            custom_format_class,
        },
        has_security: bool,
        before_field_init: bool,
        is_type_forwarder: bool,
        custom_format: u2,
    };

    pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexMap(IndexSize)) !Type {
        const raw_value = try PackedData(packed struct(u32) {
            Visibility: enum(u3) {
                NotPublic = 0,
                Public = 1,
                NestedPublic = 2,
                NestedPrivate = 3,
                NestedFamily = 4,
                NestedAssembly = 5,
                NestedFamANDAssem = 6,
                NestedFamORAssem = 7,
            },
            Layout: enum(u2) {
                AutoLayout = 0,
                SequentialLayout = 1,
                ExplicitLayout = 2,
            },
            ClassSemantics: enum(u1) {
                Class = 0,
                Interface = 1,
            },
            padding0: PackedPadding(u1),
            Abstract: PackedBool(u1),
            Sealed: PackedBool(u1),
            padding1: PackedPadding(u1),
            SpecialName: PackedBool(u1),
            RTSpecialName: PackedBool(u1),
            Import: PackedBool(u1),
            Serializable: PackedBool(u1),
            WindowsRuntime: PackedBool(u1),
            padding2: PackedPadding(u1),
            StringFormat: enum(u2) {
                AnsiClass = 0,
                UnicodeClass = 1,
                AutoClass = 2,
                CustomFormatClass = 3,
            },
            HasSecurity: PackedBool(u1),
            padding3: PackedPadding(u1),
            BeforeFieldInit: PackedBool(u1),
            IsTypeForwarder: PackedBool(u1),
            CustomFormat: PackedInt(u2),
            padding4: PackedPadding(u8),
        }).read(stream, sizes);

        return .{
            .visibility = switch (raw_value.Visibility) {
                .NotPublic => .not_public,
                .Public => .public,
                .NestedPublic => .nested_public,
                .NestedPrivate => .nested_private,
                .NestedFamily => .nested_family,
                .NestedAssembly => .nested_assembly,
                .NestedFamANDAssem => .nested_fam_and_assem,
                .NestedFamORAssem => .nested_fam_or_assem,
            },
            .layout = switch (raw_value.Layout) {
                .AutoLayout => .auto_layout,
                .SequentialLayout => .sequential_layout,
                .ExplicitLayout => .explicit_layout,
            },
            .class_semantics = switch (raw_value.ClassSemantics) {
                .Class => .class,
                .Interface => .interface,
            },
            .abstract = raw_value.Abstract.toBool(),
            .sealed = raw_value.Sealed.toBool(),
            .special_name = raw_value.SpecialName.toBool(),
            .rt_special_name = raw_value.RTSpecialName.toBool(),
            .import = raw_value.Import.toBool(),
            .serializable = raw_value.Serializable.toBool(),
            .windows_runtime = raw_value.WindowsRuntime.toBool(),
            .string_format = switch (raw_value.StringFormat) {
                .AnsiClass => .ansi_class,
                .UnicodeClass => .unicode_class,
                .AutoClass => .auto_class,
                .CustomFormatClass => .custom_format_class,
            },
            .has_security = raw_value.HasSecurity.toBool(),
            .before_field_init = raw_value.BeforeFieldInit.toBool(),
            .is_type_forwarder = raw_value.IsTypeForwarder.toBool(),
            .custom_format = raw_value.CustomFormat.toInt(),
        };
    }
};

pub const TableStream = struct {
    reserved0: u32,
    major_version: u8,
    minor_version: u8,
    heap_sizes: std.enums.EnumFieldStruct(Heap, IndexSize, null),
    reserved1: u8,
    valid: std.enums.EnumFieldStruct(Table, bool, null),
    sorted: std.enums.EnumFieldStruct(Table, bool, null),
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

        var heap_sizes: std.enums.EnumFieldStruct(Heap, IndexSize, null) = undefined;

        inline for (comptime std.meta.tags(Heap)) |heap| {
            @field(heap_sizes, @tagName(heap)) = switch (raw_table_stream_0.HeapSizes & heap.flagBit()) {
                0 => .small,
                else => .large,
            };
        }

        var valid: std.enums.EnumFieldStruct(Table, bool, null) = undefined;
        var sorted: std.enums.EnumFieldStruct(Table, bool, null) = undefined;
        var rows = try std.ArrayList(u32).initCapacity(allocator, @popCount(raw_table_stream_0.Valid));
        errdefer rows.deinit();
        var row_counts: std.enums.EnumFieldStruct(Table, u32, null) = undefined;

        inline for (comptime std.meta.tags(Table)) |table| {
            const table_bit = @as(u64, 1) << table.number();
            @field(valid, @tagName(table)) = raw_table_stream_0.Valid & table_bit != 0;
            @field(sorted, @tagName(table)) = raw_table_stream_0.Sorted & table_bit != 0;

            @field(row_counts, @tagName(table)) = blk: switch (@field(valid, @tagName(table))) {
                true => {
                    const row_count = try reader.readInt(u32, .little);
                    rows.appendAssumeCapacity(row_count);
                    break :blk row_count;
                },
                false => 0,
            };
        }

        var index_sizes: IndexMap(IndexSize) = undefined;
        index_sizes.heap = heap_sizes;

        inline for (comptime std.meta.tags(Table)) |table| {
            @field(index_sizes.table, @tagName(table)) = .calcFromRowCounts(0, &.{@field(row_counts, @tagName(table))});
        }

        inline for (comptime std.meta.tags(CodedIndexKind)) |index| {
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
            .heap_sizes = heap_sizes,
            .reserved1 = raw_table_stream_0.Reserved1,
            .valid = valid,
            .sorted = sorted,
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
