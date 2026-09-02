import json
import re
import stat
import subprocess
import unittest
from pathlib import Path


RECIPES = Path(__file__).resolve().parents[1]


class RecipeFileTests(unittest.TestCase):
    def test_release_versions_and_checksums_are_pinned(self):
        installer = (RECIPES / "docker" / "install-runtime.sh").read_text()
        self.assertIn('HERDR_VERSION="0.8.2"', installer)
        self.assertIn('ATTACHED_VERSION="0.2.3"', installer)
        for digest in (
            "976150a14d490c94b243ea2e1a7eb2dfb67f12e36b182db90936f6728e6aecf4",
            "f55610658e1c2e0d2aaef730b4b2ab885f7f8ba00285ab372bfb14f2e3d5b40d",
            "d20cabdcb4e3b8e6d7b3119d0d8af9f6032cd73a78c887f4fc7e1392d9dea16c",
            "fee75516eb03947960e695264b51404a453ecbccaffbf3821b907588ef600956",
        ):
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertIn(digest, installer)
        self.assertIn("sha256sum -c -", installer)
        self.assertNotIn("curl |", installer)

    def test_cloudflare_versions_and_images_match(self):
        agent_package = json.loads((RECIPES / "cloudflare-agent" / "package.json").read_text())
        container_package = json.loads(
            (RECIPES / "cloudflare-containers" / "package.json").read_text()
        )
        sandbox_version = agent_package["dependencies"]["@cloudflare/sandbox"]
        sandbox_dockerfile = (
            RECIPES / "docker" / "Dockerfile.cloudflare-sandbox"
        ).read_text()
        self.assertIn(f"cloudflare/sandbox:{sandbox_version}", sandbox_dockerfile)
        self.assertEqual(agent_package["dependencies"]["agents"], "0.22.0")
        self.assertEqual(
            container_package["dependencies"]["@cloudflare/containers"], "0.3.7"
        )
        for package in (agent_package, container_package):
            self.assertEqual(package["devDependencies"]["typescript"], "5.9.3")
            self.assertEqual(package["devDependencies"]["wrangler"], "4.128.0")
            for section in ("dependencies", "devDependencies"):
                for version in package[section].values():
                    self.assertRegex(version, r"^\d+\.\d+\.\d+(?:\.\d+)?$")

    def test_wrangler_configs_reference_existing_images_and_no_plaintext_secrets(self):
        expected_secret_names = {
            "ATTACHED_PUBLISH_BUNDLE",
            "ATTACHED_LOCAL_PASSWORD",
            "CONTROL_API_TOKEN",
            "AGENT_API_TOKEN",
        }
        for project in ("cloudflare-containers", "cloudflare-agent"):
            config_path = RECIPES / project / "wrangler.jsonc"
            config = json.loads(config_path.read_text())
            self.assertEqual(len(config["containers"]), 1)
            image = (config_path.parent / config["containers"][0]["image"]).resolve()
            self.assertTrue(image.is_file(), image)
            variables = config.get("vars", {})
            self.assertTrue(expected_secret_names.isdisjoint(variables))
            self.assertIn("new_sqlite_classes", config["migrations"][0])

    def test_dockerfiles_do_not_bake_runtime_secrets(self):
        for dockerfile in (RECIPES / "docker").glob("Dockerfile*"):
            contents = dockerfile.read_text()
            lines = contents.splitlines()
            self.assertRegex(lines[0], r"^# syntax=.*@sha256:[0-9a-f]{64}$")
            first_from = next(line for line in lines if line.startswith("FROM "))
            self.assertRegex(first_from, r"@sha256:[0-9a-f]{64}$")
            self.assertNotRegex(contents, r"(?im)^\s*(ARG|ENV)\s+.*(PASSWORD|BUNDLE|TOKEN)")
            self.assertNotIn(":latest", contents)
            self.assertNotIn("COPY .env", contents)

        portable = (RECIPES / "docker" / "Dockerfile").read_text()
        compose = (RECIPES / "docker" / "compose.yaml").read_text()
        self.assertIn("USER herdr", portable)
        self.assertIn("ATTACHED_RUN_AS_UID=10001", portable)
        self.assertNotIn("HEALTHCHECK", portable)
        self.assertIn('user: "0:0"', compose)
        self.assertIn("healthcheck:", compose)
        self.assertIn("read_only: true", compose)
        for capability in ("CHOWN", "DAC_OVERRIDE", "SETGID", "SETUID"):
            self.assertIn(f"- {capability}", compose)

    def test_shell_files_parse_and_are_executable(self):
        scripts = [
            RECIPES / "docker" / "entrypoint.sh",
            RECIPES / "docker" / "install-runtime.sh",
            RECIPES / "remote-hosts" / "build-and-push.sh",
        ]
        for script in scripts:
            result = subprocess.run(
                ["sh", "-n", str(script)], capture_output=True, text=True, check=False
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(script.stat().st_mode & stat.S_IXUSR, script)

    def test_ephemeral_manifests_take_secrets_from_platform_stores(self):
        kubernetes = (RECIPES / "remote-hosts" / "kubernetes.yaml").read_text()
        self.assertIn("secretKeyRef:", kubernetes)
        self.assertNotIn("stringData:", kubernetes)
        self.assertIn("readOnlyRootFilesystem: true", kubernetes)
        self.assertIn("fsGroup: 10001", kubernetes)
        self.assertIn("automountServiceAccountToken: false", kubernetes)
        self.assertIn("startupProbe:", kubernetes)
        self.assertIn("type: Recreate", kubernetes)
        self.assertRegex(kubernetes, r"image: .*@sha256:[0-9a-f]{64}")

        workflow = (RECIPES / "remote-hosts" / "github-actions.yml").read_text()
        self.assertIn("secrets.ATTACHED_PUBLISH_BUNDLE", workflow)
        self.assertIn("secrets.ATTACHED_LOCAL_PASSWORD", workflow)
        self.assertIn("ATTACHED_PUBLISH_BUNDLE_FILE=/run/secrets/", workflow)
        self.assertIn("--no-healthcheck", workflow)
        self.assertIn("sudo chown root:root", workflow)
        self.assertNotRegex(workflow, r"(?m)--env ATTACHED_PUBLISH_BUNDLE\s*$")
        action_refs = re.findall(r"uses:\s+[^@\s]+@([^\s]+)", workflow)
        self.assertTrue(action_refs)
        for reference in action_refs:
            self.assertRegex(reference, r"^[0-9a-f]{40}$")

    def test_every_recipe_markdown_discloses_ai_assistance(self):
        markdown_files = [
            path for path in RECIPES.rglob("*.md") if "node_modules" not in path.parts
        ]
        self.assertGreaterEqual(len(markdown_files), 5)
        for document in markdown_files:
            self.assertIn("AI contribution notice", document.read_text(), document)

    def test_lockfile_covers_both_cloudflare_projects(self):
        lockfile = (RECIPES / "pnpm-lock.yaml").read_text()
        self.assertIn("cloudflare-agent:", lockfile)
        self.assertIn("cloudflare-containers:", lockfile)
        self.assertIn("@cloudflare/sandbox", lockfile)
        self.assertIn("@cloudflare/containers", lockfile)

    def test_repository_links_and_validates_recipes(self):
        repository = RECIPES.parent
        self.assertIn("[`recipes/`](recipes/)", (repository / "README.md").read_text())
        workflow = (repository / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn("recipes/**", workflow)
        self.assertIn("pnpm check", workflow)
        self.assertIn("docker build --tag attached-herdr:ci docker", workflow)


if __name__ == "__main__":
    unittest.main()
