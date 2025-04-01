# TimeTagger Setup Guide for Portainer

This guide will help you deploy TimeTagger using Portainer, a web-based Docker management interface.

## Prerequisites

- Portainer installed and running
- Docker and Docker Compose installed on the host
- Internet access to pull Docker images

## Option 1: Deploy Using the Forked Docker Image (Recommended)

This method uses the pre-built TimeTagger image from the hsonixcode fork on GitHub Container Registry.

1. **Log in to Portainer**

2. **Create a New Stack**
   - Go to "Stacks" in the left sidebar
   - Click "Add stack"
   - Give your stack a name (e.g., "timetagger")

3. **Add the Docker Compose File**
   - Copy the contents from the `portainer-docker-compose.yml` file 
   - Paste it into the "Web editor" field
   - Ensure the image is set to `ghcr.io/hsonixcode/timetagger:latest`

4. **Customize Environment Variables**
   - **IMPORTANT:** Change the default credentials `admin:admin` to something secure
   - Adjust other environment variables as needed

5. **Deploy the Stack**
   - Click "Deploy the stack"
   - Wait for Portainer to create the containers

## Option 2: Build from Source Using a Custom Dockerfile

Use this option if you need to customize the TimeTagger installation.

1. **Log in to Portainer**

2. **Create a New Stack**
   - Go to "Stacks" in the left sidebar
   - Click "Add stack"
   - Name your stack (e.g., "timetagger-custom")

3. **Modify the Docker Compose File**
   - Copy the contents from `portainer-docker-compose.yml`
   - Replace the `image: ghcr.io/hsonixcode/timetagger:latest` line with:
     ```yaml
     build:
       context: https://github.com/hsonixcode/timetagger.git
       dockerfile: Dockerfile
     ```

4. **Add the Dockerfile**
   - Create a new Dockerfile on the host where Portainer runs
   - Copy the contents from `portainer-Dockerfile` to this file
   - Ensure the Dockerfile is configured to clone from https://github.com/hsonixcode/timetagger.git

5. **Deploy the Stack**
   - Click "Deploy the stack"
   - Wait for Portainer to build the image and create containers

## Accessing TimeTagger

Once deployed, access TimeTagger at http://YOUR_SERVER_IP:8000/timetagger/

## Troubleshooting

### "No module named timetagger" Error

This error occurs when the timetagger package isn't installed correctly. To fix:

1. **Check if the Container is Running**
   - In Portainer, go to "Containers" and make sure the timetagger container is running

2. **Inspect Container Logs**
   - Click on the container name
   - Go to the "Logs" tab to view error messages

3. **Enter the Container Shell**
   - Go to the "Console" tab
   - Select "Connect" to open a shell
   
4. **Verify Installation**
   - Run `python -c "import timetagger; print(timetagger.__file__)"`
   - If this gives an error, the package is not installed correctly

5. **Fix Installation**
   - Run `cd /app && pip install -e .`
   - Restart the container

### Database Connection Issues

If TimeTagger can't connect to the database:

1. **Check PostgreSQL Container**
   - Make sure the postgres container is running

2. **Verify Network Connectivity**
   - Inside the timetagger container shell, run:
     ```
     ping postgres
     ```
   - It should be reachable

3. **Check Database URL**
   - Verify the `TIMETAGGER_DB_URL` environment variable is correct

## Data Persistence

All data is stored in two Docker volumes:
- `postgres_data`: Contains the PostgreSQL database
- `timetagger_data`: Contains TimeTagger configuration and files

Backup these volumes regularly for data safety.

## Security Considerations

1. **Change Default Credentials**
   - Change `TIMETAGGER_CREDENTIALS` from the default `admin:admin`
   
2. **Consider Using a Reverse Proxy**
   - For HTTPS support, consider placing TimeTagger behind Traefik, Nginx, or Caddy

3. **Apply Network Restrictions**
   - Limit access to the TimeTagger server based on your needs

## Updating TimeTagger

To update TimeTagger when a new version is released:

1. **Using the Forked Image**
   - In Portainer, go to your stack
   - Click "Editor"
   - Click "Pull and redeploy"

2. **Using a Custom Build**
   - Update your local clone of the fork
   - Rebuild the Docker image
   - Redeploy the stack 