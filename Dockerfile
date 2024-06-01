FROM python:3.12

# Set the working directory
WORKDIR /code

# Copy the requirements of your application code into the container
COPY requirements.txt ./

# Install other dependencies listed in requirements.txt
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Copy the rest of your application code into the container
COPY . .

# Specify the command to run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
