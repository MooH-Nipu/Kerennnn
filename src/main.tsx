import React from 'react';
import ReactDOM from 'react-dom/client';
import '@stisla/css';
import '../styles.css';
import './styles/ui-improvements.css';
import './styles/stisla-bridge.css';
import { ErrorBoundary } from './components/shared/ErrorBoundary';
import { App } from './App';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
