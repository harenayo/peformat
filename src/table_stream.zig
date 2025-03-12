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

    pub fn id(comptime table: Table) u6 {
        return @field(properties, @tagName(table))[0];
    }

    pub fn Column(table: Table) type {
        return @field(properties, @tagName(table))[1];
    }

    pub fn validBit(comptime table: Table) u64 {
        return @as(u64, 1) << table.id();
    }

    pub fn Row(table: Table) type {
        const table_columns = std.enums.values(table.Column());
        var row_struct_fields: [table_columns.len]std.builtin.Type.StructField = undefined;

        for (&row_struct_fields, table_columns) |*row_struct_field, table_column| row_struct_field.* = .{
            .name = @tagName(table_column),
            .type = table_column.Type(),
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(table_column.Type()),
        };

        return @Type(.{ .@"struct" = .{
            .layout = .auto,
            .fields = &row_struct_fields,
            .decls = &.{},
            .is_tuple = false,
        } });
    }

    pub fn readRow(comptime table: Table, stream: *std.io.FixedBufferStream([]const u8), sizes: IndexSizes) !table.Row() {
        var row: table.Row() = undefined;
        const row_struct_fields = @typeInfo(table.Row()).@"struct".fields;
        inline for (row_struct_fields) |row_struct_field| @field(row, row_struct_field.name) = try row_struct_field.type.read(stream, sizes);
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
        .generation = IntType(2),
        .name = IndexType(.{ .heap = .string }),
        .mvid = IndexType(.{ .heap = .guid }),
        .enc_id = IndexType(.{ .heap = .guid }),
        .enc_base_id = IndexType(.{ .heap = .guid }),
    };

    pub fn Type(column: ModuleColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const TypeRefColumn = enum {
    resolution_scope,
    type_name,
    type_namespace,

    const properties: std.enums.EnumFieldStruct(TypeRefColumn, type, null) = .{
        .resolution_scope = CodedIndexType(.resolution_scope),
        .type_name = IndexType(.{ .heap = .string }),
        .type_namespace = IndexType(.{ .heap = .string }),
    };

    pub fn Type(column: TypeRefColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const TypeDefColumn = enum {
    flags,
    type_name,
    type_namespace,
    extends,
    field_list,
    method_list,

    const properties: std.enums.EnumFieldStruct(TypeDefColumn, type, null) = .{
        .flags = IntType(4),
        .type_name = IndexType(.{ .heap = .string }),
        .type_namespace = IndexType(.{ .heap = .string }),
        .extends = CodedIndexType(.type_def_or_ref),
        .field_list = IndexType(.{ .table = .field }),
        .method_list = IndexType(.{ .table = .method_def }),
    };

    pub fn Type(column: TypeDefColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const FieldColumn = enum {
    flags,
    name,
    signature,

    const properties: std.enums.EnumFieldStruct(FieldColumn, type, null) = .{
        .flags = IntType(2),
        .name = IndexType(.{ .heap = .string }),
        .signature = IndexType(.{ .heap = .blob }),
    };

    pub fn Type(column: FieldColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const MethodDefColumn = enum {
    rva,
    impl_flags,
    flags,
    name,
    signature,
    param_list,

    const properties: std.enums.EnumFieldStruct(MethodDefColumn, type, null) = .{
        .rva = IntType(4),
        .impl_flags = IntType(2),
        .flags = IntType(2),
        .name = IndexType(.{ .heap = .string }),
        .signature = IndexType(.{ .heap = .blob }),
        .param_list = IndexType(.{ .table = .param }),
    };

    pub fn Type(column: MethodDefColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const ParamColumn = enum {
    flags,
    sequence,
    name,

    const properties: std.enums.EnumFieldStruct(ParamColumn, type, null) = .{
        .flags = IntType(2),
        .sequence = IntType(2),
        .name = IndexType(.{ .heap = .string }),
    };

    pub fn Type(column: ParamColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const InterfaceImplColumn = enum {
    class,
    interface,

    const properties: std.enums.EnumFieldStruct(InterfaceImplColumn, type, null) = .{
        .class = IndexType(.{ .table = .type_def }),
        .interface = CodedIndexType(.type_def_or_ref),
    };

    pub fn Type(column: InterfaceImplColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const MemberRefColumn = enum {
    class,
    name,
    signature,

    const properties: std.enums.EnumFieldStruct(MemberRefColumn, type, null) = .{
        .class = CodedIndexType(.member_ref_parent),
        .name = IndexType(.{ .heap = .string }),
        .signature = IndexType(.{ .heap = .blob }),
    };

    pub fn Type(column: MemberRefColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const ConstantColumn = enum {
    type,
    parent,
    value,

    const properties: std.enums.EnumFieldStruct(ConstantColumn, type, null) = .{
        .type = IntType(2),
        .parent = CodedIndexType(.has_constant),
        .value = IndexType(.{ .heap = .blob }),
    };

    pub fn Type(column: ConstantColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const CustomAttributeColumn = enum {
    parent,
    type,
    value,

    const properties: std.enums.EnumFieldStruct(CustomAttributeColumn, type, null) = .{
        .parent = CodedIndexType(.has_custom_attribute),
        .type = CodedIndexType(.custom_attribute_type),
        .value = IndexType(.{ .heap = .blob }),
    };

    pub fn Type(column: CustomAttributeColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const FieldMarshalColumn = enum {
    parent,
    native_type,

    const properties: std.enums.EnumFieldStruct(FieldMarshalColumn, type, null) = .{
        .parent = CodedIndexType(.has_field_marshal),
        .native_type = IndexType(.{ .heap = .blob }),
    };

    pub fn Type(column: FieldMarshalColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const DeclSecurityColumn = enum {
    action,
    parent,
    permission_set,

    const properties: std.enums.EnumFieldStruct(DeclSecurityColumn, type, null) = .{
        .action = IntType(2),
        .parent = CodedIndexType(.has_decl_security),
        .permission_set = IndexType(.{ .heap = .blob }),
    };

    pub fn Type(column: DeclSecurityColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const ClassLayoutColumn = enum {
    packing_size,
    class_size,
    parent,

    const properties: std.enums.EnumFieldStruct(ClassLayoutColumn, type, null) = .{
        .packing_size = IntType(2),
        .class_size = IntType(4),
        .parent = IndexType(.{ .table = .type_def }),
    };

    pub fn Type(column: ClassLayoutColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const FieldLayoutColumn = enum {
    offset,
    field,

    const properties: std.enums.EnumFieldStruct(FieldLayoutColumn, type, null) = .{
        .offset = IntType(4),
        .field = IndexType(.{ .table = .field }),
    };

    pub fn Type(column: FieldLayoutColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const StandAloneSigColumn = enum {
    signature,

    const properties: std.enums.EnumFieldStruct(StandAloneSigColumn, type, null) = .{
        .signature = IndexType(.{ .heap = .blob }),
    };

    pub fn Type(column: StandAloneSigColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const EventMapColumn = enum {
    parent,
    event_list,

    const properties: std.enums.EnumFieldStruct(EventMapColumn, type, null) = .{
        .parent = IndexType(.{ .table = .type_def }),
        .event_list = IndexType(.{ .table = .event }),
    };

    pub fn Type(column: EventMapColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const EventColumn = enum {
    event_flags,
    name,
    event_type,

    const properties: std.enums.EnumFieldStruct(EventColumn, type, null) = .{
        .event_flags = IntType(2),
        .name = IndexType(.{ .heap = .string }),
        .event_type = CodedIndexType(.type_def_or_ref),
    };

    pub fn Type(column: EventColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const PropertyMapColumn = enum {
    parent,
    property_list,

    const properties: std.enums.EnumFieldStruct(PropertyMapColumn, type, null) = .{
        .parent = IndexType(.{ .table = .type_def }),
        .property_list = IndexType(.{ .table = .property }),
    };

    pub fn Type(column: PropertyMapColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const PropertyColumn = enum {
    flags,
    name,
    type,

    const properties: std.enums.EnumFieldStruct(PropertyColumn, type, null) = .{
        .flags = IntType(2),
        .name = IndexType(.{ .heap = .string }),
        .type = IndexType(.{ .heap = .blob }),
    };

    pub fn Type(column: PropertyColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const MethodSemanticsColumn = enum {
    semantics,
    method,
    association,

    const properties: std.enums.EnumFieldStruct(MethodSemanticsColumn, type, null) = .{
        .semantics = IntType(2),
        .method = IndexType(.{ .table = .method_def }),
        .association = CodedIndexType(.has_semantics),
    };

    pub fn Type(column: MethodSemanticsColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const MethodImplColumn = enum {
    class,
    method_body,
    method_declaration,

    const properties: std.enums.EnumFieldStruct(MethodImplColumn, type, null) = .{
        .class = IndexType(.{ .table = .type_def }),
        .method_body = CodedIndexType(.method_def_or_ref),
        .method_declaration = CodedIndexType(.method_def_or_ref),
    };

    pub fn Type(column: MethodImplColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const ModuleRefColumn = enum {
    name,

    const properties: std.enums.EnumFieldStruct(ModuleRefColumn, type, null) = .{
        .name = IndexType(.{ .heap = .string }),
    };

    pub fn Type(column: ModuleRefColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const TypeSpecColumn = enum {
    signature,

    const properties: std.enums.EnumFieldStruct(TypeSpecColumn, type, null) = .{
        .signature = IndexType(.{ .heap = .blob }),
    };

    pub fn Type(column: TypeSpecColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const ImplMapColumn = enum {
    mapping_flags,
    member_forwarded,
    import_name,
    import_scope,

    const properties: std.enums.EnumFieldStruct(ImplMapColumn, type, null) = .{
        .mapping_flags = IntType(2),
        .member_forwarded = CodedIndexType(.member_forwarded),
        .import_name = IndexType(.{ .heap = .string }),
        .import_scope = IndexType(.{ .table = .module_ref }),
    };

    pub fn Type(column: ImplMapColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const FieldRvaColumn = enum {
    rva,
    field,

    const properties: std.enums.EnumFieldStruct(FieldRvaColumn, type, null) = .{
        .rva = IntType(4),
        .field = IndexType(.{ .table = .field }),
    };

    pub fn Type(column: FieldRvaColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const AssemblyColumn = enum {
    hash_alg_id,
    versions,
    flags,
    public_key,
    name,
    culture,

    const properties: std.enums.EnumFieldStruct(AssemblyColumn, type, null) = .{
        .hash_alg_id = IntType(4),
        .versions = IntType(8),
        .flags = IntType(4),
        .public_key = IndexType(.{ .heap = .blob }),
        .name = IndexType(.{ .heap = .string }),
        .culture = IndexType(.{ .heap = .string }),
    };

    pub fn Type(column: AssemblyColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const AssemblyProcessorColumn = enum {
    processor,

    const properties: std.enums.EnumFieldStruct(AssemblyProcessorColumn, type, null) = .{
        .processor = IntType(4),
    };

    pub fn Type(column: AssemblyProcessorColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const AssemblyOsColumn = enum {
    os_platform_id,
    os_major_version,
    os_minor_version,

    const properties: std.enums.EnumFieldStruct(AssemblyOsColumn, type, null) = .{
        .os_platform_id = IntType(4),
        .os_major_version = IntType(4),
        .os_minor_version = IntType(4),
    };

    pub fn Type(column: AssemblyOsColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const AssemblyRefColumn = enum {
    versions,
    flags,
    public_key_or_token,
    name,
    culture,
    hash_value,

    const properties: std.enums.EnumFieldStruct(AssemblyRefColumn, type, null) = .{
        .versions = IntType(8),
        .flags = IntType(4),
        .public_key_or_token = IndexType(.{ .heap = .blob }),
        .name = IndexType(.{ .heap = .string }),
        .culture = IndexType(.{ .heap = .string }),
        .hash_value = IndexType(.{ .heap = .blob }),
    };

    pub fn Type(column: AssemblyRefColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const AssemblyRefProcessorColumn = enum {
    processor,
    assembly_ref,

    const properties: std.enums.EnumFieldStruct(AssemblyRefProcessorColumn, type, null) = .{
        .processor = IntType(4),
        .assembly_ref = IndexType(.{ .table = .assembly_ref }),
    };

    pub fn Type(column: AssemblyRefProcessorColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const AssemblyRefOsColumn = enum {
    os_platform_id,
    os_major_version,
    os_minor_version,
    assembly_ref,

    const properties: std.enums.EnumFieldStruct(AssemblyRefOsColumn, type, null) = .{
        .os_platform_id = IntType(4),
        .os_major_version = IntType(4),
        .os_minor_version = IntType(4),
        .assembly_ref = IndexType(.{ .table = .assembly_ref }),
    };

    pub fn Type(column: AssemblyRefOsColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const FileColumn = enum {
    flags,
    name,
    hash_value,

    const properties: std.enums.EnumFieldStruct(FileColumn, type, null) = .{
        .flags = IntType(4),
        .name = IndexType(.{ .heap = .string }),
        .hash_value = IndexType(.{ .heap = .blob }),
    };

    pub fn Type(column: FileColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const ExportedTypeColumn = enum {
    flags,
    type_def_id,
    type_name,
    type_namespace,
    implementation,

    const properties: std.enums.EnumFieldStruct(ExportedTypeColumn, type, null) = .{
        .flags = IntType(4),
        .type_def_id = IntType(4),
        .type_name = IndexType(.{ .heap = .string }),
        .type_namespace = IndexType(.{ .heap = .string }),
        .implementation = CodedIndexType(.implementation),
    };

    pub fn Type(column: ExportedTypeColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const ManifestResourceColumn = enum {
    offset,
    flags,
    name,
    implementation,

    const properties: std.enums.EnumFieldStruct(ManifestResourceColumn, type, null) = .{
        .offset = IntType(4),
        .flags = IntType(4),
        .name = IndexType(.{ .heap = .string }),
        .implementation = CodedIndexType(.implementation),
    };

    pub fn Type(column: ManifestResourceColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const NestedClassColumn = enum {
    nested_class,
    enclosing_class,

    const properties: std.enums.EnumFieldStruct(NestedClassColumn, type, null) = .{
        .nested_class = IndexType(.{ .table = .type_def }),
        .enclosing_class = IndexType(.{ .table = .type_def }),
    };

    pub fn Type(column: NestedClassColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const GenericParamColumn = enum {
    number,
    flags,
    owner,
    name,

    const properties: std.enums.EnumFieldStruct(GenericParamColumn, type, null) = .{
        .number = IntType(2),
        .flags = IntType(2),
        .owner = CodedIndexType(.type_or_method_def),
        .name = IndexType(.{ .heap = .string }),
    };

    pub fn Type(column: GenericParamColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const MethodSpecColumn = enum {
    method,
    instantiation,

    const properties: std.enums.EnumFieldStruct(MethodSpecColumn, type, null) = .{
        .method = CodedIndexType(.method_def_or_ref),
        .instantiation = IndexType(.{ .heap = .blob }),
    };

    pub fn Type(column: MethodSpecColumn) type {
        return @field(properties, @tagName(column));
    }
};

pub const GenericParamConstraintColumn = enum {
    owner,
    constraint,

    const properties: std.enums.EnumFieldStruct(GenericParamConstraintColumn, type, null) = .{
        .owner = IndexType(.{ .table = .generic_param }),
        .constraint = CodedIndexType(.type_def_or_ref),
    };

    pub fn Type(column: GenericParamConstraintColumn) type {
        return @field(properties, @tagName(column));
    }
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
        const table_values = comptime std.enums.values(Table);
        comptime var result: []const Table = &.{};

        inline for (table_values) |table_value| {
            @setEvalBranchQuota(4000);

            if (@field(tag_values, @tagName(table_value))) |_| {
                result = result ++ .{table_value};
            }
        }

        return result;
    }

    pub fn Tag(comptime index: CodedIndex) type {
        const tag_bits = index.tagBits();

        const Int = @Type(.{ .int = .{
            .signedness = .unsigned,
            .bits = tag_bits,
        } });

        const tag_values = index.tagValues();
        const tag_values_fields = @typeInfo(@TypeOf(tag_values)).@"struct".fields;
        var tag_fields: []const std.builtin.Type.EnumField = &.{};

        for (tag_values_fields) |tags_struct_field| {
            if (@field(tag_values, tags_struct_field.name)) |tag_value| {
                tag_fields = tag_fields ++ .{std.builtin.Type.EnumField{
                    .name = tags_struct_field.name,
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

pub fn IntType(bytes: u16) type {
    const Int = @Type(.{ .int = .{
        .signedness = .unsigned,
        .bits = 8 * bytes,
    } });

    return struct {
        value: Int,

        pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexSizes) !IntType(bytes) {
            _ = sizes;
            const value = try stream.reader().readInt(Int, .little);
            return .{ .value = value };
        }
    };
}

pub fn IndexType(target: union(enum) {
    heap: Heap,
    table: Table,
    coded: CodedIndex,
}) type {
    return struct {
        value: u32,

        pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexSizes) !IndexType(target) {
            const size = switch (target) {
                .heap => |heap| @field(sizes.heap, @tagName(heap)),
                .table => |table| @field(sizes.table, @tagName(table)),
                .coded => |index| @field(sizes.coded, @tagName(index)),
            };

            const value = switch (size) {
                .small => (try IntType(2).read(stream, sizes)).value,
                .large => (try IntType(4).read(stream, sizes)).value,
            };

            return .{ .value = value };
        }
    };
}

pub fn CodedIndexType(target: CodedIndex) type {
    return struct {
        tag: target.Tag(),
        value: u32,

        pub fn read(stream: *std.io.FixedBufferStream([]const u8), sizes: IndexSizes) !CodedIndexType(target) {
            const raw_value = (try IndexType(.{ .coded = target }).read(stream, sizes)).value;
            var tag_mask: u32 = 0;
            for (0..target.tagBits()) |i| tag_mask |= @as(u32, 1) << @intCast(i);
            const tag = try std.meta.intToEnum(target.Tag(), raw_value & tag_mask);
            const value = raw_value >> @intCast(target.tagBits());

            return .{
                .tag = tag,
                .value = value,
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

        const table_values = comptime std.enums.values(Table);
        var valid_vector = raw_table_stream_0.Valid;
        var rows = try std.ArrayList(u32).initCapacity(allocator, @popCount(raw_table_stream_0.Valid));
        errdefer rows.deinit();
        var table_row_counts: std.enums.EnumFieldStruct(Table, u32, 0) = .{};

        inline for (table_values) |table_value| {
            const valid_bit = table_value.validBit();

            if (valid_vector & valid_bit != 0) {
                valid_vector &= ~valid_bit;
                const table_row_count = try reader.readInt(u32, .little);
                rows.appendAssumeCapacity(table_row_count);
                @field(table_row_counts, @tagName(table_value)) = table_row_count;
            }
        }

        if (valid_vector != 0) return error.PeInvalidTableValidVector;
        var index_sizes: IndexSizes = undefined;
        const heap_values = comptime std.enums.values(Heap);
        const coded_values = comptime std.enums.values(CodedIndex);

        inline for (heap_values) |heap_value| {
            @field(index_sizes.heap, @tagName(heap_value)) = switch (heap_value.flagBit() & raw_table_stream_0.HeapSizes) {
                0 => .small,
                else => .large,
            };
        }

        inline for (table_values) |table_value| {
            @field(index_sizes.table, @tagName(table_value)) = .calcFromRowCounts(0, &.{@field(table_row_counts, @tagName(table_value))});
        }

        inline for (coded_values) |coded_value| {
            const tag_bits = coded_value.tagBits();
            const coded_tables = comptime coded_value.tables();
            var tags_row_counts: [coded_tables.len]u32 = undefined;

            inline for (&tags_row_counts, coded_tables) |*tags_row_count, coded_table| {
                tags_row_count.* = @field(table_row_counts, @tagName(coded_table));
            }

            @field(index_sizes.coded, @tagName(coded_value)) = .calcFromRowCounts(tag_bits, &tags_row_counts);
        }

        var initialized_tables = std.enums.EnumSet(Table).initEmpty();
        var tables: Tables = undefined;

        errdefer {
            @setEvalBranchQuota(6000);

            inline for (table_values) |table_tag| {
                if (initialized_tables.contains(table_tag)) {
                    @field(tables, @tagName(table_tag)).deinit();
                }
            }
        }

        inline for (table_values) |table_tag| {
            const table_row_count = @field(table_row_counts, @tagName(table_tag));
            var table_rows = try std.ArrayList(table_tag.Row()).initCapacity(allocator, table_row_count);
            errdefer table_rows.deinit();
            for (0..table_row_count) |_| table_rows.appendAssumeCapacity(try table_tag.readRow(&stream, index_sizes));
            @field(tables, @tagName(table_tag)) = table_rows;
            initialized_tables.insert(table_tag);
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
        const tables_struct_fields = @typeInfo(Tables).@"struct".fields;

        inline for (tables_struct_fields) |tables_struct_field| {
            @field(stream.tables, tables_struct_field.name).deinit();
        }
    }
};

pub const Tables = blk: {
    const table_tags = std.enums.values(Table);
    var tables_struct_fields: [table_tags.len]std.builtin.Type.StructField = undefined;

    for (&tables_struct_fields, table_tags) |*tables_struct_field, table_tag| {
        const TablesFieldType = std.ArrayList(table_tag.Row());

        tables_struct_field.* = .{
            .name = @tagName(table_tag),
            .type = TablesFieldType,
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(TablesFieldType),
        };
    }

    break :blk @Type(.{ .@"struct" = .{
        .layout = .auto,
        .fields = &tables_struct_fields,
        .decls = &.{},
        .is_tuple = false,
    } });
};
