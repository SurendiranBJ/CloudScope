import test from 'node:test';
import assert from 'node:assert/strict';

test('authInterceptor injects bearer token from localStorage', async () => {
  // Setup global mocks for localStorage
  let storage = {};
  globalThis.localStorage = {
    getItem: (key) => storage[key] || null,
    setItem: (key, val) => { storage[key] = val; },
    removeItem: (key) => { delete storage[key]; }
  };
  globalThis.window = {
    dispatchEvent: () => {}
  };

  storage['cloudscope_token'] = 'test-token-123';

  // Import the apiClient and its interceptor
  const { apiClient } = await import('../src/api/client.ts');
  
  // The interceptor is registered. We can manually trigger it to see if it modifies config.
  // Axios interceptors are stored in apiClient.interceptors.request.handlers
  // But wait, the handlers array is internal. 
  // Let's just create a dummy config and pass it to the interceptor function.
  // Alternatively, we can inspect the handlers array.
  
  const handlers = apiClient.interceptors.request.handlers;
  // Get the registered fulfilled handler
  const requestInterceptor = handlers[0].fulfilled;

  let config = { headers: {} };
  config = await requestInterceptor(config);

  assert.equal(config.headers.Authorization, 'Bearer test-token-123', 'Bearer token should be injected');
});

test('authInterceptor does not inject token if missing', async () => {
  let storage = {};
  globalThis.localStorage = {
    getItem: (key) => storage[key] || null,
    setItem: (key, val) => { storage[key] = val; },
    removeItem: (key) => { delete storage[key]; }
  };
  globalThis.window = {
    dispatchEvent: () => {}
  };

  const { apiClient } = await import('../src/api/client.ts');
  
  // Clear handlers to simulate fresh state if needed, or just use the existing one
  const handlers = apiClient.interceptors.request.handlers;
  const requestInterceptor = handlers[handlers.length - 1].fulfilled;

  let config = { headers: {} };
  config = await requestInterceptor(config);

  assert.equal(config.headers.Authorization, undefined, 'Authorization header should be undefined');
});
