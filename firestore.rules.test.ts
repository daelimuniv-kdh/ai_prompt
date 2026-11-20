/**
 * Adversarial "Dirty Dozen" security rule test vectors for /prompts/{promptId}.
 * Mirrors the invariants enforced in firestore.rules and firebase-blueprint.json.
 */

export interface DirtyDozenCase {
  name: string;
  operation: 'create' | 'update' | 'delete';
  auth: { email?: string; email_verified?: boolean } | null;
  promptId: string;
  payload?: Record<string, unknown>;
  expected: 'PERMISSION_DENIED';
}

export const DIRTY_DOZEN_CASES: DirtyDozenCase[] = [
  {
    name: '01. Unauthenticated guest create',
    operation: 'create',
    auth: null,
    promptId: 'prompt-guest-1',
    payload: {
      title: '테스트',
      category: '사진 합성',
      content: '내용',
      createdAt: 'SERVER_TIMESTAMP',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '02. Non-admin authenticated user create',
    operation: 'create',
    auth: { email: 'user@example.com', email_verified: true },
    promptId: 'prompt-user-1',
    payload: {
      title: '테스트',
      category: '사진 합성',
      content: '내용',
      createdAt: 'SERVER_TIMESTAMP',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '03. Unverified admin email spoof attack',
    operation: 'create',
    auth: { email: 'aikdh0914@gmail.com', email_verified: false },
    promptId: 'prompt-spoof-1',
    payload: {
      title: '테스트',
      category: '사진 합성',
      content: '내용',
      createdAt: 'SERVER_TIMESTAMP',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '04. Non-admin delete attempt',
    operation: 'delete',
    auth: { email: 'user@example.com', email_verified: true },
    promptId: 'sample-1',
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '05. Invalid ID with slash or special characters',
    operation: 'create',
    auth: { email: 'aikdh0914@gmail.com', email_verified: true },
    promptId: '../invalid/id',
    payload: {
      title: '테스트',
      category: '사진 합성',
      content: '내용',
      createdAt: 'SERVER_TIMESTAMP',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '06. Ghost / shadow field injection',
    operation: 'create',
    auth: { email: 'aikdh0914@gmail.com', email_verified: true },
    promptId: 'prompt-shadow-1',
    payload: {
      title: '테스트',
      category: '사진 합성',
      content: '내용',
      createdAt: 'SERVER_TIMESTAMP',
      isAdmin: true,
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '07. Missing required title field',
    operation: 'create',
    auth: { email: 'aikdh0914@gmail.com', email_verified: true },
    promptId: 'prompt-missing-title',
    payload: {
      category: '사진 합성',
      content: '내용',
      createdAt: 'SERVER_TIMESTAMP',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '08. Oversized title (>100 chars)',
    operation: 'create',
    auth: { email: 'aikdh0914@gmail.com', email_verified: true },
    promptId: 'prompt-long-title',
    payload: {
      title: 'a'.repeat(101),
      category: '사진 합성',
      content: '내용',
      createdAt: 'SERVER_TIMESTAMP',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '09. Invalid category outside allowlist',
    operation: 'create',
    auth: { email: 'aikdh0914@gmail.com', email_verified: true },
    promptId: 'prompt-bad-cat',
    payload: {
      title: '테스트',
      category: '기타',
      content: '내용',
      createdAt: 'SERVER_TIMESTAMP',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '10. Oversized content (>10000 chars)',
    operation: 'create',
    auth: { email: 'aikdh0914@gmail.com', email_verified: true },
    promptId: 'prompt-huge-content',
    payload: {
      title: '테스트',
      category: '사진 합성',
      content: 'a'.repeat(10001),
      createdAt: 'SERVER_TIMESTAMP',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '11. Spoofed client createdAt timestamp',
    operation: 'create',
    auth: { email: 'aikdh0914@gmail.com', email_verified: true },
    promptId: 'prompt-spoof-time',
    payload: {
      title: '테스트',
      category: '사진 합성',
      content: '내용',
      createdAt: new Date(0).toISOString(),
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    name: '12. Mutating immutable createdAt on update',
    operation: 'update',
    auth: { email: 'aikdh0914@gmail.com', email_verified: true },
    promptId: 'prompt-user-1',
    payload: {
      title: '수정된 제목',
      category: '스타일 변환',
      content: '수정된 내용',
      createdAt: 'DIFFERENT_TIMESTAMP',
    },
    expected: 'PERMISSION_DENIED',
  },
];
