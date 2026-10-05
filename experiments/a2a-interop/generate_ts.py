import argparse
import json
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--workspace", type=Path, required=True)
args = parser.parse_args()
root = args.workspace.resolve()
template = {
    "version": "v2",
    "inputs": [{"proto_file": str(root / "a2a-itk/protos/instruction.proto")}],
    "plugins": [
        {
            "remote": "buf.build/community/stephenh-ts-proto:v2.11.0",
            "out": str(root / "a2a-js/itk/pb"),
            "opt": [
                "oneof=unions-value",
                "importSuffix=.js",
                "outputServices=false",
                "env=node",
                "esModuleInterop=true",
                "outputJsonMethods=true",
                "outputEncodeMethods=true",
                "outputPartialMethods=true",
                "snakeToCamel=keys",
                "emitImportedFiles=false",
                "useDate=string",
            ],
        }
    ],
}
subprocess.run(
    [
        str(root / "node_modules/@bufbuild/buf-win32-arm64/bin/buf.exe"),
        "generate",
        "--template",
        json.dumps(template),
    ],
    cwd=root / "a2a-itk",
    check=True,
    creationflags=subprocess.CREATE_NO_WINDOW,
)
