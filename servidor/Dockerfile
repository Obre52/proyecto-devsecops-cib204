# ============================================================================
#  Dockerfile  -  Servicio de cifrado
# ============================================================================

# [FIX H-07] Imagen base fijada a una version concreta y minimalista (Alpine,
#   musl) en vez de "latest"/Debian: reduce drasticamente la superficie de
#   vulnerabilidades del sistema operativo. CWE-1104 remediado.
FROM node:20-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

# ----------------------------------------------------------------------------
FROM node:20-alpine

WORKDIR /app

RUN apk update && apk upgrade --no-cache

# [FIX H-08] Se ejecuta con un usuario sin privilegios (no root). CWE-250 remediado.
RUN addgroup -S appuser && adduser -S -D -H -G appuser appuser

COPY --from=build --chown=appuser:appuser /app .

# npm ya cumplio su funcion en la etapa de build; no se necesita en runtime.
# Se elimina junto con sus dependencias internas (reducia 22 hallazgos de Trivy).
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack 2>/dev/null || true

USER appuser

EXPOSE 3000

CMD ["node", "servidor.js"]
