import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import ClientAuthorization from './components/ClientAuthorization.tsx';
import './index.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {window.location.pathname.startsWith('/connect/') ? <ClientAuthorization /> : <App />}
  </StrictMode>,
);
