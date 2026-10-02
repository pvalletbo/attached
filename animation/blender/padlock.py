"""Build a tiny original Blender prop; no downloaded models or textures.

Rebuild the clip: npm run blender
Inspect the scene: open output/blender/padlock.blend in Blender.
Validate without rendering: blender -b -t 4 --python blender/padlock.py -- --check
"""
import argparse
import math
from pathlib import Path
import sys

import bpy
from mathutils import Vector

FPS = 30
FRAMES = 90
SIZE = 512


def material(name, rgb, metallic=0.0, roughness=0.35):
    mat = bpy.data.materials.new(name)
    mat.use_nodes = True
    shader = mat.node_tree.nodes.get("Principled BSDF")
    # Convert display colors to linear-light shader inputs.
    linear = tuple(c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb)
    shader.inputs["Base Color"].default_value = (*linear, 1)
    shader.inputs["Metallic"].default_value = metallic
    shader.inputs["Roughness"].default_value = roughness
    return mat


def box(name, location, scale, mat, bevel=0):
    bpy.ops.mesh.primitive_cube_add(size=2, location=location)
    obj = bpy.context.object
    obj.name = name
    obj.scale = scale
    bpy.ops.object.transform_apply(location=False, rotation=False, scale=True)
    if bevel:
        modifier = obj.modifiers.new("Soft edges", "BEVEL")
        modifier.width = bevel
        modifier.segments = 4
        obj.modifiers.new("Weighted normals", "WEIGHTED_NORMAL")
    obj.data.materials.append(mat)
    return obj


def area(name, position, power, size, color):
    light = bpy.data.lights.new(name, "AREA")
    light.energy = power
    light.shape = "DISK"
    light.size = size
    light.color = color
    obj = bpy.data.objects.new(name, light)
    bpy.context.collection.objects.link(obj)
    obj.location = position
    obj.rotation_euler = (Vector((0, 0, 0.5)) - obj.location).to_track_quat("-Z", "Y").to_euler()


def build():
    bpy.ops.object.select_all(action="SELECT")
    bpy.ops.object.delete(use_global=False)
    scene = bpy.context.scene
    scene.render.engine = "CYCLES"
    scene.cycles.device = "CPU"
    scene.cycles.samples = 16
    scene.cycles.use_denoising = True
    scene.render.resolution_x = scene.render.resolution_y = SIZE
    scene.render.resolution_percentage = 100
    scene.render.fps = FPS
    scene.render.film_transparent = True
    scene.render.image_settings.file_format = "PNG"
    scene.render.image_settings.color_mode = "RGBA"
    scene.view_settings.view_transform = "Standard"
    scene.frame_start, scene.frame_end = 1, FRAMES
    scene.world.use_nodes = True
    scene.world.node_tree.nodes["Background"].inputs["Strength"].default_value = 0.25

    red = material("Ink red / enamel", (0.92, 0.29, 0.18), 0.15)
    acid = material("Acid yellow / metal", (0.87, 1.0, 0.44), 0.55, 0.25)
    black = material("Keyhole", (0.025, 0.025, 0.022), 0.0, 0.8)
    body = box("Lock body", (0, 0, 0), (1.12, 0.43, 0.85), red, 0.14)

    # A bent round bar: two straight legs and a semicircular crown.
    curve = bpy.data.curves.new("Bent shackle", "CURVE")
    curve.dimensions = "3D"
    curve.bevel_depth, curve.bevel_resolution = 0.16, 4
    points = [(-0.74, 0, 0.65), (-0.74, 0, 1.26)]
    points += [(0.74 * math.cos(t), 0, 1.26 + 0.74 * math.sin(t))
               for t in [math.pi - i * math.pi / 32 for i in range(33)]]
    points += [(0.74, 0, 0.65)]
    spline = curve.splines.new("POLY")
    spline.points.add(len(points) - 1)
    for point, xyz in zip(spline.points, points):
        point.co = (*xyz, 1)
    shackle = bpy.data.objects.new("Closed shackle", curve)
    bpy.context.collection.objects.link(shackle)
    shackle.data.materials.append(acid)

    bpy.ops.mesh.primitive_cylinder_add(vertices=48, radius=0.19, depth=0.018,
                                      location=(0, -0.44, 0.12), rotation=(math.pi / 2, 0, 0))
    hole = bpy.context.object
    hole.name = "Keyhole circle"
    hole.data.materials.append(black)
    slot = box("Keyhole slot", (0, -0.447, -0.12), (0.085, 0.012, 0.22), black)

    rig = bpy.data.objects.new("Turntable", None)
    bpy.context.collection.objects.link(rig)
    for obj in (body, shackle, hole, slot):
        obj.parent = rig
    # One revolution in exactly 90 frames; omit the duplicated endpoint frame.
    rig.rotation_euler = (math.radians(9), math.radians(-8), 0)
    rig.keyframe_insert(data_path="rotation_euler", frame=1)
    rig.rotation_euler.z = 2 * math.pi
    rig.keyframe_insert(data_path="rotation_euler", frame=FRAMES + 1)
    # Blender 4.4+ uses layered actions; Blender 4.2 exposes fcurves directly.
    action = rig.animation_data.action
    if hasattr(action, "fcurves"):
        fcurves = action.fcurves
    else:
        fcurves = action.layers[0].strips[0].channelbag(rig.animation_data.action_slot).fcurves
    for fcurve in fcurves:
        for key in fcurve.keyframe_points:
            key.interpolation = "LINEAR"

    camera_data = bpy.data.cameras.new("Camera")
    camera = bpy.data.objects.new("Camera", camera_data)
    bpy.context.collection.objects.link(camera)
    camera.location = (3.3, -7, 3.1)
    camera.rotation_euler = (Vector((0, 0, 0.55)) - camera.location).to_track_quat("-Z", "Y").to_euler()
    camera_data.type, camera_data.ortho_scale = "ORTHO", 4.7
    scene.camera = camera
    area("Softbox", (1, -4, 5), 450, 4, (1.0, 0.9, 0.78))
    area("Cobalt fill", (-4, -1, 2), 220, 3, (0.48, 0.63, 1.0))
    area("Rim", (1, 4, 4), 700, 3, (1.0, 1.0, 0.9))
    scene.frame_set(1)
    return scene, rig


def validate(scene, rig):
    assert scene.render.resolution_x == scene.render.resolution_y == SIZE
    assert scene.frame_end - scene.frame_start + 1 == FRAMES
    assert scene.render.fps == FPS and scene.camera is not None
    assert len(rig.children) == 4
    scene.frame_set(1)
    start = rig.rotation_euler.z
    scene.frame_set(FRAMES + 1)
    assert math.isclose(rig.rotation_euler.z - start, 2 * math.pi, abs_tol=1e-5)
    scene.frame_set(1)
    print("PASS: padlock geometry, camera, dimensions, and seamless turntable timing")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--still", action="store_true")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "output" / "blender")
    args = parser.parse_args(sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else [])
    scene, rig = build()
    validate(scene, rig)
    if args.check:
        return
    args.output.mkdir(parents=True, exist_ok=True)
    bpy.ops.wm.save_as_mainfile(filepath=str(args.output / "padlock.blend"))
    scene.render.filepath = str(args.output / "padlock-")
    if args.still:
        scene.render.filepath = str(args.output / "preview.png")
        bpy.ops.render.render(write_still=True)
    else:
        bpy.ops.render.render(animation=True)


if __name__ == "__main__":
    main()
