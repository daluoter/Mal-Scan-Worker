/// <reference types="vite/client" />

interface ImportMetaEnv {
    readonly VITE_API_BASE_URL: string
    readonly VITE_BASE_PATH: string
    readonly VITE_DEPLOYMENT_MODE?: string
    readonly VITE_API_DEPLOYMENT?: string
}

interface ImportMeta {
    readonly env: ImportMetaEnv
}
