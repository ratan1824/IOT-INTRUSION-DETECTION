import psycopg2
from psycopg2 import OperationalError

connection = None
try:
    connection = psycopg2.connect(
        database = "testing_server",
        host = "localhost",
        port = "5432"
    )
    print("Connection to PostgreSQL DB successful")
except OperationalError as e:
    print(f"The error '{e}' occurred")


create_table_query = """
SELECT * FROM users;
"""


try:
    cursor = connection.cursor()
    cursor.execute(create_table_query)
    rows = cursor.fetchall()
    for row in rows:
        print(row)
    connection.commit()
except Exception as error:
    print(error)
connection.close()