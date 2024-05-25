import json

def fix_sarif(file_path):
    with open(file_path, 'r') as file:
        sarif = json.load(file)

    for run in sarif.get('runs', []):
        for rule in run.get('tool', {}).get('driver', {}).get('rules', []):
            if 'properties' in rule and 'security-severity' in rule['properties']:
                if rule['properties']['security-severity'] is None:
                    rule['properties']['security-severity'] = 0
                elif rule['properties']['security-severity'] == "undefined":
                    rule['properties']['security-severity'] = 0

    with open(file_path, 'w') as file:
        json.dump(sarif, file, indent=2)

if __name__ == "__main__":
    fix_sarif('snyk.sarif')
