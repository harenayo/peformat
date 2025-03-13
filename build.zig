const std = @import("std");

pub fn build(b: *std.Build) !void {
    var ast = try std.zig.Ast.parse(b.allocator, @embedFile("build.zig.zon"), .zon);
    defer ast.deinit(b.allocator);
    var zoir = try std.zig.ZonGen.generate(b.allocator, ast, .{ .parse_str_lits = false });
    defer zoir.deinit(b.allocator);
    const manifest = std.zig.Zoir.Node.Index.root.get(zoir).struct_literal;

    const name = for (0.., manifest.names) |i, field| {
        if (!std.mem.eql(u8, field.get(zoir), "name")) continue;
        break manifest.vals.at(@intCast(i)).get(zoir).enum_literal.get(zoir);
    } else unreachable;

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const module = b.addModule(name, .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const zigwin32 = b.dependency("zigwin32", .{});
    const win32_module = zigwin32.module("win32");
    module.addImport("win32", win32_module);

    const check_compile = b.addLibrary(.{
        .name = name,
        .root_module = module,
    });

    const check_step = b.step("check", "Check the library");
    check_step.dependOn(&check_compile.step);

    const test_compile = b.addTest(.{
        .root_module = module,
    });

    const test_run = b.addRunArtifact(test_compile);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);

    const docs_compile = b.addLibrary(.{
        .name = name,
        .root_module = module,
    });

    const docs_install = b.addInstallDirectory(.{
        .source_dir = docs_compile.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });

    docs_install.step.dependOn(&docs_compile.step);
    const docs_step = b.step("docs", "Generate a document");
    docs_step.dependOn(&docs_install.step);
}
