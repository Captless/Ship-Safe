from __future__ import annotations

from scanner.models import ScanTarget, FileSnapshot

MANIFESTS = {
    "package.json": ("node", {"nodejs", "javascript"}),
    "pnpm-lock.yaml": ("node", {"nodejs", "javascript"}),
    "yarn.lock": ("node", {"nodejs", "javascript"}),
    "package-lock.json": ("node", {"nodejs", "javascript"}),
    "requirements.txt": ("python", {"python"}),
    "pyproject.toml": ("python", {"python"}),
    "Pipfile": ("python", {"python"}),
    "poetry.lock": ("python", {"python"}),
    "setup.py": ("python", {"python"}),
    "manage.py": ("django", {"python", "django"}),
    "composer.json": ("php", {"php"}),
    "artisan": ("laravel", {"php", "laravel"}),
    "Gemfile": ("ruby", {"ruby"}),
    "go.mod": ("go", {"go"}),
    "Cargo.toml": ("rust", {"rust"}),
    ".csproj": ("dotnet", {"dotnet"}),
}

FRAMEWORK_MARKERS = {
    "supabase": "supabase",
    "firebase": "firebase",
    "stripe": "stripe",
    "@prisma/client": "prisma",
    "prisma": "prisma",
    "next": "nextjs",
    "react": "react",
    "vue": "vue",
    "vite": "vite",
    "express": "express",
    "fastapi": "fastapi",
    "flask": "flask",
    "django": "django",
    "laravel": "laravel",
    "@anthropic-ai/sdk": "anthropic",
    "openai": "openai",
}


def detect_scan_target(root: str, files: list[FileSnapshot]) -> ScanTarget:
    target = ScanTarget(root=root, files=files)
    names = {f.path.split("/")[-1] for f in files}
    for name, (ptype, fws) in MANIFESTS.items():
        if name in names:
            target.project_type = ptype
            target.frameworks.update(fws)
            break
    if target.project_type == "unknown":
        for f in files:
            base = f.path.split("/")[-1].lower()
            if base.endswith((".js", ".ts", ".jsx", ".tsx")):
                target.project_type = "node"
                target.frameworks.update({"nodejs", "javascript"})
            elif base.endswith((".py",)):
                target.project_type = "python"
                target.frameworks.add("python")
            elif base.endswith((".php",)):
                target.project_type = "php"
                target.frameworks.add("php")
            elif base.endswith((".go",)):
                target.project_type = "go"
                target.frameworks.add("go")
            elif base.endswith((".rb",)):
                target.project_type = "ruby"
                target.frameworks.add("ruby")
    for f in files:
        name = f.path.split("/")[-1].lower()
        for marker, fw in FRAMEWORK_MARKERS.items():
            if marker.lower() in name or marker.lower() in f.content[:2000].lower():
                target.frameworks.add(fw)
    return target
