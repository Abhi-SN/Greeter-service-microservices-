
FROM nginx:1.27-alpine

## Copy our static content (the index.html file) into the Nginx HTML directory
COPY index.html /usr/share/nginx/html

##  Copy our custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
