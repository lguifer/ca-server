table_content = ""  # Global variable to store table content

def display_data(data):
    global table_content  # Refer to the global variable to update it
    table_rows = ""  # Initialize the table_rows variable as an empty string

    # Prepare data for the table
    data_lines = data.splitlines()  # Split the input data into lines
    table_rows += "".join(f"<tr><td>{line}</td></tr>" for line in data_lines)  # Create rows for the table

    # Format the table content as HTML
    table_content = f"<table class='table table-bordered'><tbody>{table_rows}</tbody></table>"

    # Optionally, you could return the table_content or render it in a template if needed
    # return render_template('index.html', table_content=table_content)
