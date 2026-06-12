import bcrypt from 'bcryptjs';
import { nanoid } from 'nanoid';

const data = {
  users: [],
  tenants: [],
  memberships: [],
  tasks: [],
  invitations: [],
  oauthSessions: new Map(),
  authCodes: new Map()
};

const TOKEN_LIFETIME_SECONDS = 60 * 60;

function normalizeUsernameCandidate(value) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '');
}

function generateUsername(email) {
  const baseCandidate = normalizeUsernameCandidate(email
    .split('@')[0]
  ) || `user${nanoid(6)}`;
  let candidate = baseCandidate;
  let attempt = 1;
  while (data.users.some((user) => user.username === candidate)) {
    candidate = `${baseCandidate}${attempt++}`;
  }
  return candidate;
}

export function createUser({ email, password, name, username }) {
  const existing = data.users.find((user) => user.email.toLowerCase() === email.toLowerCase());
  if (existing) {
    throw new Error('Email already registered');
  }
  const passwordHash = bcrypt.hashSync(password, 10);
  let finalUsername;
  if (username && username.trim()) {
    const baseCandidate = normalizeUsernameCandidate(username.trim());
    if (!baseCandidate) {
      throw new Error('Username must contain letters or numbers');
    }
    let candidate = baseCandidate;
    let attempt = 1;
    while (data.users.some((user) => user.username === candidate)) {
      candidate = `${baseCandidate}${attempt++}`;
    }
    finalUsername = candidate;
  } else {
    finalUsername = generateUsername(email);
  }
  const user = {
    id: nanoid(),
    email,
    passwordHash,
    name,
    username: finalUsername,
    aboutMe: '',
    createdAt: new Date().toISOString()
  };
  data.users.push(user);
  return user;
}

export function getUserById(id) {
  return data.users.find((user) => user.id === id) || null;
}

export function getUserByUsername(username) {
  const normalized = username.toLowerCase();
  return data.users.find((user) => user.username === normalized) || null;
}

export function findUserByEmail(email) {
  return data.users.find((user) => user.email.toLowerCase() === email.toLowerCase()) || null;
}

export function verifyUserCredentials(email, password) {
  const user = findUserByEmail(email);
  if (!user) {
    return null;
  }
  const valid = bcrypt.compareSync(password, user.passwordHash);
  return valid ? user : null;
}

export function verifyUserCredentialsByUsername(username, password) {
  if (!username || !password) {
    return null;
  }
  const normalized = normalizeUsernameCandidate(username.trim());
  if (!normalized) {
    return null;
  }
  const user = getUserByUsername(normalized);
  if (!user) {
    return null;
  }
  const valid = bcrypt.compareSync(password, user.passwordHash);
  return valid ? user : null;
}

export function setUserAboutMe(userId, aboutMe) {
  const user = getUserById(userId);
  if (!user) {
    throw new Error('User not found');
  }
  user.aboutMe = aboutMe;
  return user;
}

export function updateUserIdentifiers(userId, { email, username }) {
  const user = getUserById(userId);
  if (!user) {
    throw new Error('User not found');
  }
  if (typeof email === 'string') {
    const trimmedEmail = email.trim();
    if (!trimmedEmail) {
      throw new Error('Email is required');
    }
    const duplicateEmail = data.users.find(
      (other) => other.id !== userId && other.email.toLowerCase() === trimmedEmail.toLowerCase()
    );
    if (duplicateEmail) {
      throw new Error('Email already in use');
    }
    user.email = trimmedEmail;
  }
  if (typeof username === 'string') {
    const normalized = normalizeUsernameCandidate(username.trim());
    if (!normalized) {
      throw new Error('Username must contain letters or numbers');
    }
    const duplicateUsername = data.users.find(
      (other) => other.id !== userId && other.username === normalized
    );
    if (duplicateUsername) {
      throw new Error('Username already in use');
    }
    user.username = normalized;
  }
  return user;
}

export function createTenant({ name, ownerId }) {
  const tenant = {
    id: nanoid(),
    name,
    ownerId,
    createdAt: new Date().toISOString()
  };
  data.tenants.push(tenant);
  return tenant;
}

export function getTenantById(id) {
  return data.tenants.find((tenant) => tenant.id === id) || null;
}

export function listTenantsByOwner(ownerId) {
  return data.tenants.filter((tenant) => tenant.ownerId === ownerId);
}

export function createMembership({ tenantId, userId, role }) {
  const membership = {
    id: nanoid(),
    tenantId,
    userId,
    role,
    createdAt: new Date().toISOString()
  };
  data.memberships.push(membership);
  return membership;
}

export function getMembership(userId, tenantId) {
  return data.memberships.find((m) => m.userId === userId && m.tenantId === tenantId) || null;
}

export function listMembershipsByUser(userId) {
  return data.memberships.filter((m) => m.userId === userId);
}

export function listTenantMembers(tenantId) {
  return data.memberships.filter((m) => m.tenantId === tenantId);
}

export function createTask({ tenantId, createdBy, title, description }) {
  const task = {
    id: nanoid(),
    tenantId,
    title,
    description,
    createdBy,
    completed: false,
    createdAt: new Date().toISOString(),
    completedAt: null
  };
  data.tasks.push(task);
  return task;
}

export function toggleTaskCompletion(taskId, tenantId, completedBy) {
  const task = data.tasks.find((t) => t.id === taskId && t.tenantId === tenantId);
  if (!task) {
    throw new Error('Task not found');
  }
  task.completed = !task.completed;
  task.completedAt = task.completed ? new Date().toISOString() : null;
  task.completedBy = task.completed ? completedBy : null;
  return task;
}

export function listTasksByTenant(tenantId) {
  return data.tasks.filter((task) => task.tenantId === tenantId);
}

export function deleteTask(taskId, tenantId) {
  const idx = data.tasks.findIndex((t) => t.id === taskId && t.tenantId === tenantId);
  if (idx === -1) {
    return false;
  }
  data.tasks.splice(idx, 1);
  return true;
}

export function createInvitation({ tenantId, email }) {
  const invitation = {
    id: nanoid(),
    tenantId,
    email,
    token: nanoid(32),
    createdAt: new Date().toISOString(),
    usedAt: null
  };
  data.invitations.push(invitation);
  return invitation;
}

export function getInvitationByToken(token) {
  return data.invitations.find((inv) => inv.token === token) || null;
}

export function markInvitationUsed(token) {
  const invitation = getInvitationByToken(token);
  if (!invitation) {
    throw new Error('Invitation not found');
  }
  invitation.usedAt = new Date().toISOString();
  return invitation;
}

export function listInvitationsByTenant(tenantId) {
  return data.invitations.filter((invitation) => invitation.tenantId === tenantId);
}

export function createOAuthSession(userId) {
  const sessionId = nanoid();
  data.oauthSessions.set(sessionId, {
    userId,
    createdAt: Date.now()
  });
  return sessionId;
}

export function getOAuthSession(sessionId) {
  return data.oauthSessions.get(sessionId) || null;
}

export function destroyOAuthSession(sessionId) {
  data.oauthSessions.delete(sessionId);
}

export function storeAuthCode({ code, userId, clientId, redirectUri, scope }) {
  data.authCodes.set(code, {
    userId,
    clientId,
    redirectUri,
    scope: Array.isArray(scope) ? scope.slice() : [],
    createdAt: Date.now(),
    expiresIn: TOKEN_LIFETIME_SECONDS
  });
}

export function consumeAuthCode(code) {
  const record = data.authCodes.get(code);
  if (!record) {
    return null;
  }
  const isExpired = Date.now() - record.createdAt > record.expiresIn * 1000;
  // Do NOT delete the code on consumption so it can be reused until expiry.
  if (isExpired) {
    return null;
  }
  return record;
}

export function resetAll() {
  data.users = [];
  data.tenants = [];
  data.memberships = [];
  data.tasks = [];
  data.invitations = [];
  data.oauthSessions.clear();
  data.authCodes.clear();
}

export function getDataSnapshot() {
  return JSON.parse(JSON.stringify({
    users: data.users,
    tenants: data.tenants,
    memberships: data.memberships,
    tasks: data.tasks,
    invitations: data.invitations
  }));
}
