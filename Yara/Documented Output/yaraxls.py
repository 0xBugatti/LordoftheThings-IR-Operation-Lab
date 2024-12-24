import pandas as pd

# Define the input and output files
input_file = 'result.txt'
output_file = 'yara_scan.xlsx'

# Parse the text output
rows = []
with open(input_file, 'r') as file:
    current_rule = None
    current_file = None

    for line in file:
        line = line.strip()
        if line.startswith("rule"):
            parts = line.split(" ")
            current_rule = parts[1]  # Rule name
        elif line.startswith("0x"):
            # Parse matched strings
            parts = line.split(" ")
            offset = parts[0]
            string_id = parts[1]
            content = " ".join(parts[2:])
            rows.append({
                'Rule': current_rule,
                'File': current_file,
                'Offset': offset,
                'String ID': string_id,
                'Content': content
            })
        elif line.endswith("scanned"):
            current_file = line.split(" ")[-2]  # File being scanned

# Convert to DataFrame
df = pd.DataFrame(rows)

# Save to Excel
df.to_excel(output_file, index=False)

print(f"YARA results saved to '{output_file}'")
