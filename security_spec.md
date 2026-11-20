# Security Specification (`prompts` Collection)

## 1. Data Invariants
1. Guests (unauthenticated users) can only `get` and `list` `/prompts/{promptId}`.
2. All writes (`create`, `update`, `delete`) require an authenticated user with `request.auth.token.email_verified == true` and `request.auth.token.email == 'aikdh0914@gmail.com'`.
3. Every document in `/prompts/{promptId}` must use a valid URL-safe document ID (`^[a-zA-Z0-9_\-]+$`, max 128 chars).
4. Every document in `/prompts/{promptId}` must contain **only** the four schema keys: `title`, `category`, `content`, `createdAt`.
5. `title` must be a non-empty string (`1 <= size <= 100`).
6. `category` must strictly belong to `['사진 합성', '스타일 변환', '캐릭터·포스터']`.
7. `content` must be a non-empty string (`1 <= size <= 10000`) so long prompts (>1,000 chars) are supported while preventing resource exhaustion.
8. `createdAt` must be a `timestamp` equal to `request.time` on creation (`incoming().createdAt == request.time`).
9. Updates are restricted to editing `title`, `category`, or `content` while keeping `createdAt` immutable (`incoming().createdAt == existing().createdAt`).

## 2. The "Dirty Dozen" Adversarial Payloads
1. **Unauthenticated Create**: Guest attempts `create` -> `PERMISSION_DENIED`.
2. **Non-Admin User Create**: Authenticated non-admin email attempts `create` -> `PERMISSION_DENIED`.
3. **Unverified Admin Email Spoof**: Token with `email == 'aikdh0914@gmail.com'` and `email_verified: false` -> `PERMISSION_DENIED`.
4. **Unauthenticated / Non-Admin Update or Delete**: Non-admin attempts `update` or `delete` -> `PERMISSION_DENIED`.
5. **Invalid ID Poisoning**: Admin attempts `create` with ID `../invalid/id` -> `PERMISSION_DENIED`.
6. **Ghost / Shadow Field Injection**: Admin payload includes `{ isAdmin: true }` -> `PERMISSION_DENIED`.
7. **Missing Required Field (`title`)**: Admin payload omits `title` -> `PERMISSION_DENIED`.
8. **Oversized `title` (>100 chars)**: `title: "a".repeat(101)` -> `PERMISSION_DENIED`.
9. **Invalid `category` Enum**: `category: "기타"` -> `PERMISSION_DENIED`.
10. **Oversized `content` (>10000 chars)**: `content: "a".repeat(10001)` -> `PERMISSION_DENIED`.
11. **Spoofed `createdAt` Timestamp**: `createdAt: new Date(0)` instead of `serverTimestamp()` -> `PERMISSION_DENIED`.
12. **Mutating `createdAt` on Update**: Admin attempts to alter `createdAt` during `update` -> `PERMISSION_DENIED`.
