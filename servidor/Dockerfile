# ============================================================================
#  Dockerfile  -  Servicio de cifrado
# ============================================================================

# [FIX H-07] Imagen base fijada a una version concreta y liviana (slim) en vez
#   de "latest": build reproducible y menor superficie de ataque del SO base.
#   CWE-1104 remediado.
FROM node:20-slim AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

# ----------------------------------------------------------------------------
FROM node:20-slim

WORKDIR /app

# [FIX H-08] Se crea un usuario sin privilegios y se usa para ejecutar el
#   proceso, en vez de dejarlo correr como root. CWE-250 remediado.
RUN groupadd --system appuser && useradd --system --gid appuser --no-create-home appuser

COPY --from=build --chown=appuser:appuser /app .

USER appuser

EXPOSE 3000

CMD ["node", "servidor.js"]
