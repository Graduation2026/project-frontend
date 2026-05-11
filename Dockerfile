# Use Nginx alpine for a small footprint
FROM nginx:alpine

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our custom config
COPY default.conf /etc/nginx/conf.d/

# Copy static assets and templates
# Note: In our separation, templates/index.html is the root
COPY templates/index.html /usr/share/nginx/html/index.html
COPY static/ /usr/share/nginx/html/static/

# Expose Nginx port
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
