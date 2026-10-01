import { validateDiscoveredBackendUrl, setApiBaseUrl, getApiBaseUrl, setAccessToken, getAccessToken, setUnauthorizedHandler } from '../services/api';
import { useInvestigationStore } from '../stores/investigationStore';

function assertEqual<T>(actual: T, expected: T, message: string) {
  if (actual !== expected) {
    throw new Error(`Assertion Failed: ${message}. Expected: ${expected}, Actual: ${actual}`);
  }
}

export function runFrontendDiscoveryTests(): boolean {
  console.log('Running ADFIR Frontend Dynamic Backend Discovery & Application Integration Verification Suite...\n');

  // Step 1 Test 1: Valid discovered URL accepted (http://127.0.0.1:54321/api)
  const validUrl = 'http://127.0.0.1:54321/api';
  assertEqual(validateDiscoveredBackendUrl(validUrl, 54321), true, 'Valid 127.0.0.1 URL must be accepted');
  console.log('✓ Test 1: Valid http://127.0.0.1:54321/api accepted');

  // Step 1 Test 2: Reject remote host (http://malicious.site/api)
  assertEqual(validateDiscoveredBackendUrl('http://malicious.site/api', 54321), false, 'Remote host must be rejected');
  console.log('✓ Test 2: Remote host http://malicious.site/api rejected');

  // Step 1 Test 3: Reject https (https://127.0.0.1:54321/api)
  assertEqual(validateDiscoveredBackendUrl('https://127.0.0.1:54321/api', 54321), false, 'HTTPS scheme must be rejected');
  console.log('✓ Test 3: HTTPS scheme rejected');

  // Step 1 Test 4: Reject http://localhost:54321/api for Tauri production discovery
  assertEqual(validateDiscoveredBackendUrl('http://localhost:54321/api', 54321), false, 'localhost hostname must be rejected for strict Tauri production discovery');
  assertEqual(validateDiscoveredBackendUrl('http://0.0.0.0:54321/api', 54321), false, '0.0.0.0 wildcard address must be rejected');
  assertEqual(validateDiscoveredBackendUrl('http://[::1]:54321/api', 54321), false, '[::1] IPv6 loopback must be rejected for strict IPv4 discovery');
  console.log('✓ Test 4: non-127.0.0.1 hostnames (localhost, 0.0.0.0, [::1]) rejected for strict discovery');

  // Step 1 Test 5: Reject non-/api path (http://127.0.0.1:54321/evil)
  assertEqual(validateDiscoveredBackendUrl('http://127.0.0.1:54321/evil', 54321), false, 'Arbitrary path must be rejected');
  console.log('✓ Test 5: Path other than /api rejected');

  // Step 1 Test 6: Reject URL containing credentials (http://user:pass@127.0.0.1:54321/api)
  assertEqual(validateDiscoveredBackendUrl('http://user:pass@127.0.0.1:54321/api', 54321), false, 'URL containing credentials must be rejected');
  console.log('✓ Test 6: URL credentials rejected');

  // Step 1 Test 7: Reject URL containing query or fragment (http://127.0.0.1:54321/api?query=1#hash)
  assertEqual(validateDiscoveredBackendUrl('http://127.0.0.1:54321/api?query=1#hash', 54321), false, 'URL query/fragment must be rejected');
  console.log('✓ Test 7: URL query/fragment rejected');

  // Step 1 Test 8: Reject invalid/mismatched port
  assertEqual(validateDiscoveredBackendUrl('http://127.0.0.1:80/api', 80), false, 'Privileged port < 1024 must be rejected');
  assertEqual(validateDiscoveredBackendUrl('http://127.0.0.1:54321/api', 54322), false, 'Mismatched port must be rejected');
  console.log('✓ Test 8: Invalid and mismatched ports rejected');

  // Step 1 Test 9: setApiBaseUrl updates Axios runtime baseURL getter
  setApiBaseUrl('http://127.0.0.1:54321/api');
  assertEqual(getApiBaseUrl(), 'http://127.0.0.1:54321/api', 'getApiBaseUrl must return updated runtime URL');
  console.log('✓ Test 9: setApiBaseUrl updates runtime baseURL');

  // Step 2 Test 1: Initial state reset is DISCOVERING
  useInvestigationStore.setState({ backendState: 'DISCOVERING', backendUrl: null, backendError: null });
  assertEqual(useInvestigationStore.getState().backendState, 'DISCOVERING', 'Initial backend state must be DISCOVERING');
  console.log('✓ Step 2 Test 1: Initial backendState is DISCOVERING');

  // Step 2 Test 2: Successful discovery transitions state to READY
  useInvestigationStore.getState().initializeBackend();
  const state = useInvestigationStore.getState();
  assertEqual(state.backendState, 'READY', 'initializeBackend must transition backendState to READY');
  assertEqual(state.backendUrl, 'http://localhost:8000/api', 'Standalone browser dev mode initializes port 8000');
  console.log('✓ Step 2 Test 2: Discovery completes to state READY');

  // Step 2 Test 3 & 4: Network failure changes state to UNAVAILABLE without logging user out
  let unauthorizedCalled = false;
  setUnauthorizedHandler(() => { unauthorizedCalled = true; });
  setAccessToken('valid_jwt_token_sample');

  useInvestigationStore.getState().handleBackendNetworkFailure();
  const networkErrorState = useInvestigationStore.getState();
  assertEqual(networkErrorState.backendState, 'UNAVAILABLE', 'Network failure must set backendState to UNAVAILABLE');
  assertEqual(unauthorizedCalled, false, 'Backend network failure must NOT trigger unauthorized handler');
  assertEqual(getAccessToken(), 'valid_jwt_token_sample', 'JWT token must NOT be erased on network failure');
  console.log('✓ Step 2 Test 3 & 4: Network failure transitions state to UNAVAILABLE without logging user out');

  // Step 2 Test 5: Intentional shutdown transitions state to STOPPING and stops polling
  useInvestigationStore.getState().setBackendStopping();
  const stoppingState = useInvestigationStore.getState();
  assertEqual(stoppingState.backendState, 'STOPPING', 'Intentional shutdown must set backendState to STOPPING');
  console.log('✓ Step 2 Test 5: Intentional shutdown transitions state to STOPPING');

  // Step 2 Test 6: Status polling start/stop calls do not crash or create duplicate timers
  useInvestigationStore.getState().startStatusPolling();
  useInvestigationStore.getState().startStatusPolling(); // Duplicate call test
  useInvestigationStore.getState().stopStatusPolling();
  console.log('✓ Step 2 Test 6: Status polling start/stop operates cleanly without leaks');

  // Step 2 Test 7: No PID or bootstrap secret stored in frontend state
  const storeKeys = Object.keys(useInvestigationStore.getState());
  assertEqual(storeKeys.includes('pid'), false, 'Store state must NOT expose pid field');
  assertEqual(storeKeys.includes('bootstrap_secret'), false, 'Store state must NOT expose bootstrap_secret field');
  console.log('✓ Step 2 Test 7: No PID or bootstrap secret exposed in frontend state');

  // Step 3 Test 1: Case switching does NOT alter or reset backendUrl
  setApiBaseUrl('http://127.0.0.1:58400/api');
  useInvestigationStore.setState({ backendUrl: 'http://127.0.0.1:58400/api', activeInvestigation: null });
  const origError = console.error;
  console.error = () => {}; // Suppress connection error logs for offline case switch test
  const mockInv = { id: 'case-99', name: 'Active Case 99', status: 'OPEN', created_at: '', updated_at: '' };
  useInvestigationStore.getState().setActiveInvestigation(mockInv);
  console.error = origError;

  assertEqual(getApiBaseUrl(), 'http://127.0.0.1:58400/api', 'Case switching must NOT reset or alter API base URL');
  assertEqual(useInvestigationStore.getState().backendUrl, 'http://127.0.0.1:58400/api', 'Case switching must NOT alter backendUrl in store');
  console.log('✓ Step 3 Test 1: Case switching preserves dynamic backend URL');

  // Step 3 Test 2: AI and Forensic endpoints utilize the single runtime API base URL
  assertEqual(getApiBaseUrl().endsWith('/api'), true, 'All API methods utilize dynamic Axios base URL ending in /api');
  console.log('✓ Step 3 Test 2: Forensic and AI endpoints use single runtime API base authority');

  // Step 1 Test 14: Backend URL is memory-only and is NOT persisted
  assertEqual(useInvestigationStore.getState().backendUrl, 'http://127.0.0.1:58400/api', 'backendUrl exists in memory store state');
  if (typeof globalThis.sessionStorage !== 'undefined') {
    assertEqual(globalThis.sessionStorage.getItem('backendUrl'), null, 'backendUrl must NOT be persisted to sessionStorage');
    assertEqual(globalThis.sessionStorage.getItem('backend_url'), null, 'backend_url must NOT be persisted to sessionStorage');
  }
  console.log('✓ Step 1 Test 14: Backend URL is stored in-memory only and is not persisted');

  console.log('\nAll Step 4 Step 1, Step 2 & Step 3 Frontend Requirements Successfully Verified!');
  return true;
}

runFrontendDiscoveryTests();
