# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose port 8000 for the API
EXPOSE 8000

# Define environment variables (Can be overridden at runtime)
ENV LLM_API_URL="https://api.openai.com/v1/chat/completions"
# ENV LLM_API_KEY=""  <-- Best practice: Don't bake secrets into the image

# Run the server
CMD ["python", "server.py"]
