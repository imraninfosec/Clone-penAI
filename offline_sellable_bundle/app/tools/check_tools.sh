#!/bin/bash
echo "🔍 Checking security tools..."
echo "=============================="

# Check sqlmap
if [ -f "sqlmap/sqlmap.py" ]; then
    echo "✅ sqlmap: Installed"
else
    echo "❌ sqlmap: Missing"
fi

# Check nuclei
if [ -f "nuclei" ]; then
    echo "✅ Nuclei: Installed"
else
    echo "❌ Nuclei: Missing"
fi

# Check nikto
if [ -f "nikto/program/nikto.pl" ]; then
    echo "✅ Nikto: Installed"
else
    echo "❌ Nikto: Missing"
fi

# Check katana
if [ -f "katana" ]; then
    echo "✅ Katana: Installed"
else
    echo "❌ Katana: Missing"
fi

echo "=============================="
