import asyncio
from aethersec.cli import run_full_audit
from aethersec.mock_target.server import MockTargetServer

async def main():
    server = MockTargetServer(port=8888)
    await server.start()
    print("Mock Server running on http://127.0.0.1:8888")
    await run_full_audit("http://127.0.0.1:8888", "aethersec_report.md")
    await server.stop()

if __name__ == "__main__":
    asyncio.run(main())
