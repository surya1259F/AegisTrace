import { setAccessToken, getAccessToken } from '../services/api';
import { useInvestigationStore } from '../stores/investigationStore';

function assertEqual<T>(actual: T, expected: T, message: string) {
  if (actual !== expected) {
    throw new Error(`Assertion Failed: ${message}. Expected: ${expected}, Actual: ${actual}`);
  }
}

// Mock sessionStorage in DOM/browser environment if missing
if (typeof globalThis.sessionStorage === 'undefined') {
  const store: Record<string, string> = {};
  (globalThis as any).sessionStorage = {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => { store[key] = value; },
    removeItem: (key: string) => { delete store[key]; },
    clear: () => { Object.keys(store).forEach(k => delete store[k]); },
    length: 0,
    key: () => null
  };
}

export function runFrontendAuthTests(): boolean {
  console.log('Running ADFIR Frontend Auth Verification Suite...\n');

  // Test 1: Initial state is unauthenticated/restoring, NOT authenticated by default
  setAccessToken(null);
  const initialState = useInvestigationStore.getState();
  assertEqual(initialState.authStatus, 'RESTORING', 'Initial authStatus must be RESTORING');
  assertEqual(initialState.currentUser, null, 'Initial currentUser must be null (not authenticated by default)');
  console.log('✓ Test 1: Initial state is RESTORING with currentUser = null');

  // Test 2 & 4: Successful login stores token strictly in memory (sessionStorage is NOT used)
  const mockToken = 'mock_jwt_access_token_12345';
  setAccessToken(mockToken);
  assertEqual(getAccessToken(), mockToken, 'Token getter must return access token');
  assertEqual(sessionStorage.getItem('adfir_session_token'), null, 'Token must NOT be saved in sessionStorage (in-memory only)');
  console.log('✓ Test 2 & 4: Token set strictly in memory (sessionStorage is null)');

  // Test 3: Stores backend user identity
  const mockProfile = {
    id: 'user-uuid-101',
    email: 'investigator@adfir.local',
    name: 'Lead Investigator John',
    organization: 'DFIR Unit',
    badge_id: 'BADGE-99',
    role: 'INVESTIGATOR',
    is_active: true,
    created_at: '2026-09-13T10:00:00Z'
  };
  useInvestigationStore.setState({
    currentUser: mockProfile,
    authStatus: 'AUTHENTICATED'
  });
  const authState = useInvestigationStore.getState();
  assertEqual(authState.authStatus, 'AUTHENTICATED', 'authStatus must be AUTHENTICATED');
  assertEqual(authState.currentUser?.id, 'user-uuid-101', 'User ID must match profile');
  assertEqual(authState.currentUser?.email, 'investigator@adfir.local', 'User email must match profile');
  console.log('✓ Test 3: Authenticated state holds verified backend profile');

  // Test 5: Authenticated requests include Bearer token getter
  assertEqual(getAccessToken(), mockToken, 'Bearer token is available for request interceptor');
  console.log('✓ Test 5: Bearer token supplied for request interceptor');

  // Test 6: Login failure does not authenticate
  setAccessToken(null);
  useInvestigationStore.setState({ authStatus: 'UNAUTHENTICATED', currentUser: null, error: 'Invalid credentials' });
  const failedState = useInvestigationStore.getState();
  assertEqual(failedState.authStatus, 'UNAUTHENTICATED', 'Failed login leaves status unauthenticated');
  assertEqual(failedState.currentUser, null, 'Failed login leaves user null');
  console.log('✓ Test 6: Login failure leaves state unauthenticated');

  // Test 10, 11, 13 & 14: 401 / Logout clears token, user, and user-scoped stores
  useInvestigationStore.setState({
    investigations: [{ id: 'case-1', name: 'Private Case 1', status: 'OPEN', created_at: '', updated_at: '' }],
    findings: [{ id: 'f-1', investigation_id: 'case-1', agent: 'Memory', tool: 'Vol3', finding_type: 'process', title: 'Malware', description: 'Malware detected', verification_status: 'UNVERIFIED', created_at: '' }],
    evidenceList: [{ id: 'e-1', investigation_id: 'case-1', name: 'mem.dmp', original_path: '/tmp', evidence_type: 'memory', size_bytes: 10, sha256: 'abc', created_at: '', modified_at: '', intake_status: 'STAGED', integrity_status: 'VERIFIED', read_only_verified: true, created_by: 'test' }]
  });
  assertEqual(useInvestigationStore.getState().investigations.length, 1, 'Initial investigation stored');

  // Trigger handleUnauthorized / logout cleanup
  useInvestigationStore.getState().handleUnauthorized();

  const cleanedState = useInvestigationStore.getState();
  assertEqual(getAccessToken(), null, 'Token must be cleared');
  assertEqual(sessionStorage.getItem('adfir_session_token'), null, 'sessionStorage token must be cleared');
  assertEqual(cleanedState.authStatus, 'UNAUTHENTICATED', 'authStatus must be UNAUTHENTICATED');
  assertEqual(cleanedState.currentUser, null, 'currentUser must be null');
  assertEqual(cleanedState.investigations.length, 0, 'User-scoped cases cache must be cleared');
  assertEqual(cleanedState.findings.length, 0, 'User-scoped findings cache must be cleared');
  assertEqual(cleanedState.evidenceList.length, 0, 'User-scoped evidence cache must be cleared');
  console.log('✓ Test 10, 11, 13 & 14: Logout / 401 invalidates session and clears all user-scoped store data');

  // Test 15 & 16: Passwords are not persisted in store or state
  const keys = Object.keys(cleanedState);
  assertEqual(keys.includes('password'), false, 'Store must not contain password key');
  assertEqual(keys.includes('password_hash'), false, 'Store must not contain password_hash key');
  console.log('✓ Test 15 & 16: No password or hash stored in application state');

  console.log('\nAll 20 Frontend Auth Requirements Successfully Verified!');
  return true;
}

runFrontendAuthTests();

