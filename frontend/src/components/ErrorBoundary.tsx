import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="flex-1 flex flex-col items-center justify-center p-8 text-center bg-enterprise-bg text-gray-200">
          <AlertTriangle className="w-16 h-16 text-rose-500 mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">Application Error</h2>
          <p className="text-sm text-enterprise-subtext max-w-lg mb-6">
            The page encountered an unexpected error and could not be rendered. Your session is still active, and you can navigate to another page or retry.
          </p>
          <div className="flex gap-4">
            <button
              onClick={() => this.setState({ hasError: false, error: null })}
              className="flex items-center gap-2 px-4 py-2 bg-enterprise-accent hover:bg-blue-600 text-white rounded-lg text-sm font-semibold transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
              Try Again
            </button>
            <button
              onClick={() => {
                this.setState({ hasError: false, error: null });
                window.location.href = '/';
              }}
              className="flex items-center gap-2 px-4 py-2 bg-enterprise-card hover:bg-gray-800 border border-enterprise-border text-white rounded-lg text-sm font-semibold transition-colors"
            >
              Return to Dashboard
            </button>
          </div>
          {this.state.error && (
            <div className="mt-8 text-left bg-gray-900 border border-enterprise-border rounded-lg p-4 max-w-2xl w-full overflow-auto max-h-48">
              <pre className="text-[10px] text-rose-400 font-mono">
                {this.state.error.toString()}
              </pre>
            </div>
          )}
        </div>
      );
    }

    return this.props.children;
  }
}
