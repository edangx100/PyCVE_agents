#!/bin/bash
# Start PyCVE with MCP integration

# Load .env file into shell environment so variables are in os.environ for Docker forwarding
if [ -f .env ]; then
    set -a  # automatically export all variables
    source .env
    set +a  # disable automatic export
fi

echo "Starting PyCVE with OSV MCP Integration"
echo "=" * 80

# Check if MCP server is already running
if lsof -i :3000 > /dev/null 2>&1; then
    echo "✓ OSV MCP Server already running on port 3000"
else
    echo "Starting OSV MCP Server..."
    cd /home/ed/myprojs/PyCVE/src/mcp_servers
    python osv_http_server.py > /tmp/osv_mcp_server.log 2>&1 &
    MCP_PID=$!
    sleep 3

    if lsof -i :3000 > /dev/null 2>&1; then
        echo "✓ OSV MCP Server started (PID: $MCP_PID)"
    else
        echo "✗ Failed to start OSV MCP Server"
        exit 1
    fi
fi

# Start Gradio app
echo ""
echo "Starting Gradio App..."
cd /home/ed/myprojs/PyCVE
python app.py

# Note: When you stop the Gradio app (Ctrl+C), the MCP server will keep running
# To stop MCP server: pkill -f osv_http_server.py
