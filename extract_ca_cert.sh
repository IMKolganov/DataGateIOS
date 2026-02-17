#!/bin/bash
# extract_ca_cert.sh - extracts CA certificate from .ovpn file

OVPN_FILE="$1"
OUTPUT_FILE="${OVPN_FILE}.ca.crt"

if [ -z "$OVPN_FILE" ]; then
    echo "Usage: $0 <config.ovpn>"
    exit 1
fi

if [ ! -f "$OVPN_FILE" ]; then
    echo "Error: File not found: $OVPN_FILE"
    exit 1
fi

echo "Extracting CA certificate from: $OVPN_FILE"

# Extract <ca>...</ca> section
# Remove <ca> and </ca> tags, keep only the content
sed -n '/<ca>/,/<\/ca>/p' "$OVPN_FILE" | \
    sed '1d;$d' > "$OUTPUT_FILE"

if [ ! -s "$OUTPUT_FILE" ]; then
    echo "Error: CA section not found or empty"
    rm -f "$OUTPUT_FILE"
    exit 1
fi

echo "CA certificate extracted to: $OUTPUT_FILE"
echo "Certificate length: $(wc -c < "$OUTPUT_FILE") bytes"
echo "Certificate lines: $(wc -l < "$OUTPUT_FILE")"

# Check for BEGIN/END markers
if grep -q "BEGIN CERTIFICATE" "$OUTPUT_FILE"; then
    echo "✓ BEGIN CERTIFICATE marker found"
else
    echo "⚠ WARNING: BEGIN CERTIFICATE marker not found"
fi

if grep -q "END CERTIFICATE" "$OUTPUT_FILE"; then
    echo "✓ END CERTIFICATE marker found"
    
    # Check that there are characters after END
    END_LINE=$(grep -n "END CERTIFICATE" "$OUTPUT_FILE" | cut -d: -f1)
    TOTAL_LINES=$(wc -l < "$OUTPUT_FILE")
    
    if [ "$END_LINE" -lt "$TOTAL_LINES" ]; then
        echo "✓ Characters found after END CERTIFICATE marker"
    else
        echo "⚠ WARNING: No characters after END CERTIFICATE marker"
    fi
else
    echo "⚠ WARNING: END CERTIFICATE marker not found"
fi

echo ""
echo "First 10 lines of extracted certificate:"
head -n 10 "$OUTPUT_FILE"
echo ""
echo "Last 10 lines of extracted certificate:"
tail -n 10 "$OUTPUT_FILE"
