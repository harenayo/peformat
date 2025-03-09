const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const test_compile = b.addTest(.{
        .root_module = module,
    });

    const test_run = b.addRunArtifact(test_compile);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);
}
