package auth

import (
	"testing"
	"time"

	masterstate "github.com/apernet/OpenGFW/master/state"
)

type fakeStore struct {
	hasAdmin bool
	nextID   int64
	users    map[string]struct {
		id   int64
		hash string
	}
	sessions map[string]struct {
		userID    int64
		username  string
		expiresAt time.Time
	}
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		nextID: 1,
		users: make(map[string]struct {
			id   int64
			hash string
		}),
		sessions: make(map[string]struct {
			userID    int64
			username  string
			expiresAt time.Time
		}),
	}
}

func (s *fakeStore) HasAdminUsers() (bool, error) { return s.hasAdmin, nil }

func (s *fakeStore) BootstrapAdminUser(username, passwordHash string) (int64, error) {
	if s.hasAdmin {
		return 0, ErrSetupDone
	}
	id := s.nextID
	s.nextID++
	s.users[username] = struct {
		id   int64
		hash string
	}{id: id, hash: passwordHash}
	s.hasAdmin = true
	return id, nil
}

func (s *fakeStore) CreateAdminUser(username, passwordHash string) (int64, error) {
	return s.BootstrapAdminUser(username, passwordHash)
}

func (s *fakeStore) GetAdminUserByUsername(username string) (int64, string, string, error) {
	user, ok := s.users[username]
	if !ok {
		return 0, "", "", masterstate.ErrNotFound
	}
	return user.id, username, user.hash, nil
}

func (s *fakeStore) GetAdminUserByID(id int64) (string, error) {
	for username, user := range s.users {
		if user.id == id {
			return username, nil
		}
	}
	return "", masterstate.ErrNotFound
}

func (s *fakeStore) UpdateAdminPassword(userID int64, passwordHash string) error {
	for username, user := range s.users {
		if user.id == userID {
			s.users[username] = struct {
				id   int64
				hash string
			}{id: userID, hash: passwordHash}
			return nil
		}
	}
	return masterstate.ErrNotFound
}

func (s *fakeStore) CreateAdminSession(token string, userID int64, expiresAt time.Time) error {
	username, _ := s.GetAdminUserByID(userID)
	s.sessions[token] = struct {
		userID    int64
		username  string
		expiresAt time.Time
	}{userID: userID, username: username, expiresAt: expiresAt}
	return nil
}

func (s *fakeStore) GetAdminSession(token string) (int64, string, time.Time, error) {
	session, ok := s.sessions[token]
	if !ok {
		return 0, "", time.Time{}, masterstate.ErrNotFound
	}
	return session.userID, session.username, session.expiresAt, nil
}

func (s *fakeStore) DeleteAdminSession(token string) error {
	delete(s.sessions, token)
	return nil
}

func TestSetupLoginAndStatus(t *testing.T) {
	store := newFakeStore()
	service := NewService(store)

	status, err := service.Status("")
	if err != nil {
		t.Fatalf("status failed: %v", err)
	}
	if !status.SetupRequired {
		t.Fatal("expected setup required before admin exists")
	}

	user, token, err := service.Setup("admin", "Password123")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if user.Username != "admin" || token == "" {
		t.Fatalf("unexpected setup result: %+v token=%q", user, token)
	}

	authStatus, err := service.Status(token)
	if err != nil {
		t.Fatalf("status with token failed: %v", err)
	}
	if !authStatus.Authenticated || authStatus.User == nil || authStatus.User.Username != "admin" {
		t.Fatalf("unexpected auth status: %+v", authStatus)
	}

	if _, _, err := service.Login("admin", "bad-password"); err == nil {
		t.Fatal("expected login failure with bad password")
	}

	_, loginToken, err := service.Login("admin", "Password123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if loginToken == "" {
		t.Fatal("expected session token on login")
	}
}

func TestLoginRequiresSetupBeforeAdminExists(t *testing.T) {
	store := newFakeStore()
	service := NewService(store)

	if _, _, err := service.Login("admin", "Password123"); err == nil || err != ErrSetupRequired {
		t.Fatalf("expected ErrSetupRequired, got %v", err)
	}
}

func TestSetupRejectsSecondAdminBootstrap(t *testing.T) {
	store := newFakeStore()
	service := NewService(store)

	if _, _, err := service.Setup("admin", "Password123"); err != nil {
		t.Fatalf("first setup failed: %v", err)
	}
	if _, _, err := service.Setup("admin2", "Password456"); err == nil || err != ErrSetupDone {
		t.Fatalf("expected ErrSetupDone on second setup, got %v", err)
	}
}

func TestChangePasswordRequiresCorrectCurrentPassword(t *testing.T) {
	store := newFakeStore()
	service := NewService(store)

	user, _, err := service.Setup("admin", "Password123")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	if err := service.ChangePassword(user.ID, "WrongPassword", "Password456"); err == nil || err != ErrCurrentPasswordWrong {
		t.Fatalf("expected ErrCurrentPasswordWrong, got %v", err)
	}

	if err := service.ChangePassword(user.ID, "Password123", "Password456"); err != nil {
		t.Fatalf("change password failed: %v", err)
	}

	if _, _, err := service.Login("admin", "Password123"); err == nil {
		t.Fatal("expected old password login to fail after password change")
	}
	if _, _, err := service.Login("admin", "Password456"); err != nil {
		t.Fatalf("expected new password login to succeed: %v", err)
	}
}
