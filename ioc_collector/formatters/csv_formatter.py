import csv
from io import StringIO

def format_csv(rows):
    """
    rows: list of dict
    fields: type,value,confidence,source,note
    """
    output = StringIO()
    fieldnames = ["type", "value", "confidence", "source", "note"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    return output.getvalue()