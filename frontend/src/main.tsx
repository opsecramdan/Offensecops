import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from 'react-hot-toast'
import App from './App'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30000,
      retry: 1,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
        <Toaster
          position="top-right"
          toastOptions={{
            style: {
              background: '#1a2130',
              color: '#e6edf3',
              border: '1px solid #21262d',
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: '13px',
            },
            success: {
              iconTheme: { primary: '#00d4aa', secondary: '#0a0c10' },
            },
            error: {
              iconTheme: { primary: '#ff4757', secondary: '#0a0c10' },
            },
          }}
        />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
)
