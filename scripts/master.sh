#!/bin/bash
# Master script to run Phase 1–5 for Cloud Compliance Framework
# Author: Muhammad Arslan
# Date: $(date)

# Store paths
PHASES_DIR="/home/donutt2u/projects/cloud-compliance-framework/scripts"
PROJECT_DIR="/home/donutt2u/projects/cloud-compliance-framework"
LOG_DIR="$PROJECT_DIR/logs"

# Create logs directory if not exists
mkdir -p "$LOG_DIR"

# Function to run a phase
run_phase () {
    PHASE_SCRIPT="$PHASES_DIR/phase$1_setup.sh"
    LOG_FILE="$LOG_DIR/phase$1.log"

    echo "🚀 Running Phase $1 ..."
    if [ -f "$PHASE_SCRIPT" ]; then
        bash "$PHASE_SCRIPT" > "$LOG_FILE" 2>&1
        if [ $? -eq 0 ]; then
            echo "✅ Phase $1 completed successfully. Logs: $LOG_FILE"
        else
            echo "❌ Phase $1 failed. Check logs: $LOG_FILE"
            exit 1
        fi
    else
        echo "⚠️ Phase $1 script not found at $PHASE_SCRIPT"
        exit 1
    fi
}

# Move into project dir
cd "$PROJECT_DIR" || { echo "❌ Project directory not found"; exit 1; }

# Run all phases in order
for i in 1 2 3 4 5
do
    run_phase $i
done

echo "🎉 All phases executed successfully!"

