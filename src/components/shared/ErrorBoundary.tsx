import { Component, type ReactNode } from 'react';

interface Props { children: ReactNode; }
interface State { error: Error | null; }

// Vite hashes chunk filenames per build. A tab left open across a deploy asks for
// an entry that no longer exists, so the dynamic import rejects with a fetch error.
// That is fixed by a reload, not by retrying the same import — so give it its own page.
const CHUNK_ERROR = /dynamically imported module|Loading chunk \d+ failed|Importing a module script failed|error loading dynamically imported module/i;

function isChunkLoadError(error: Error): boolean {
  return CHUNK_ERROR.test(`${error.name}: ${error.message}`);
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    const staleBuild = isChunkLoadError(error);

    return (
      <div className="app-error-page" role="alert">
        <div className="app-error-page__card">
          <span className="app-error-page__eyebrow">{staleBuild ? 'Update available' : 'Something went wrong'}</span>
          <h1>{staleBuild ? 'This page needs a refresh' : 'This section failed to load'}</h1>
          <p>
            {staleBuild
              ? 'Charlie was updated while this tab was open, so part of the app could not be fetched. Refreshing loads the new version — you stay signed in.'
              : 'An unexpected error stopped this page from rendering. Refreshing usually clears it.'}
          </p>
          {!staleBuild && <p className="app-error-page__detail">{error.message}</p>}
          <div className="app-error-page__actions">
            <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>
              Refresh page
            </button>
            {!staleBuild && (
              <button type="button" className="btn btn-secondary" onClick={() => this.setState({ error: null })}>
                Try again
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }
}
