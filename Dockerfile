FROM node:20-slim

# Install ImageMagick + Ghostscript (needed for PDF conversion)
RUN apt-get update && apt-get install -y \
    imagemagick \
    ghostscript \
    && rm -rf /var/lib/apt/lists/*

# ImageMagick by default blocks PDF conversion for security.
# This removes that restriction so it can convert PDFs to images.
RUN sed -i 's/rights="none" pattern="PDF"/rights="read|write" pattern="PDF"/' /etc/ImageMagick-6/policy.xml || true

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .

EXPOSE 5000
CMD ["node", "server.js"]
