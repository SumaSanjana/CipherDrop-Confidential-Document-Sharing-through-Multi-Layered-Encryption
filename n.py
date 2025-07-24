import sqlite3

# Connect to the database
conn = sqlite3.connect('instance/app.db')
cursor = conn.cursor()

# Query the file table for RESUME_AIE22037.pdf
cursor.execute("SELECT * FROM file WHERE filename = ?", ('RESUME_AIE22037.pdf',))
result = cursor.fetchall()

# Print the result
if result:
    print("File record found:")
    for row in result:
        print(row)
else:
    print("No record found for RESUME_AIE22037.pdf")

# Close the connection
conn.close()