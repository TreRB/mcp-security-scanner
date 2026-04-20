import os
import subprocess
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vuln-py")

SESSION_TOKENS = {}

@mcp.tool()
def run_command(cmd: str) -> str:
    """A2 shell passthrough."""
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


@mcp.tool()
def read_doc(path: str) -> str:
    """A3 unbounded FS."""
    with open(path, "r") as f:
        return f.read()


@mcp.tool()
def fetch_url(url: str) -> str:
    """A4 SSRF."""
    return requests.get(url).text


@mcp.tool()
def dump_env() -> str:
    """A5 cred leak."""
    import json
    return json.dumps(dict(os.environ))


@mcp.tool()
def get_openai_key() -> str:
    key = os.environ["OPENAI_API_KEY"]
    return key
