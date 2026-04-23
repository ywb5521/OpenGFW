package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	masterstate "github.com/apernet/OpenGFW/master/state"
	"github.com/apernet/OpenGFW/pkg/models"

	"golang.org/x/crypto/bcrypt"
)

const SessionCookieName = "opengfw_session"

var (
	ErrUnauthorized         = errors.New("unauthorized")
	ErrSetupRequired        = errors.New("admin setup required")
	ErrSetupDone            = errors.New("admin already configured")
	ErrCurrentPasswordWrong = errors.New("current password is incorrect")
)

type Store interface {
	HasAdminUsers() (bool, error)
	BootstrapAdminUser(username, passwordHash string) (int64, error)
	GetAdminUserByUsername(username string) (int64, string, string, error)
	GetAdminUserByID(id int64) (string, error)
	UpdateAdminPassword(userID int64, passwordHash string) error
	CreateAdminSession(token string, userID int64, expiresAt time.Time) error
	GetAdminSession(token string) (int64, string, time.Time, error)
	DeleteAdminSession(token string) error
}

type Service struct {
	store      Store
	sessionTTL time.Duration
}

func NewService(store Store) *Service {
	return &Service{
		store:      store,
		sessionTTL: 24 * time.Hour,
	}
}

func (s *Service) Status(token string) (models.AuthStatusResponse, error) {
	setupRequired, err := s.setupRequired()
	if err != nil {
		return models.AuthStatusResponse{}, err
	}
	response := models.AuthStatusResponse{SetupRequired: setupRequired}
	if token == "" {
		return response, nil
	}
	user, err := s.Authenticate(token)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			return response, nil
		}
		return models.AuthStatusResponse{}, err
	}
	response.Authenticated = true
	response.User = user
	return response, nil
}

func (s *Service) Setup(username, password string) (*models.AuthenticatedUser, string, error) {
	setupRequired, err := s.setupRequired()
	if err != nil {
		return nil, "", err
	}
	if !setupRequired {
		return nil, "", ErrSetupDone
	}
	if err := validateCredentials(username, password); err != nil {
		return nil, "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", err
	}
	username = strings.TrimSpace(username)
	userID, err := s.store.BootstrapAdminUser(username, string(hash))
	if err != nil {
		setupRequired, checkErr := s.setupRequired()
		if checkErr != nil {
			return nil, "", checkErr
		}
		if !setupRequired {
			return nil, "", ErrSetupDone
		}
		return nil, "", err
	}
	token, err := s.newSession(userID)
	if err != nil {
		return nil, "", err
	}
	return &models.AuthenticatedUser{ID: userID, Username: username}, token, nil
}

func (s *Service) Login(username, password string) (*models.AuthenticatedUser, string, error) {
	setupRequired, err := s.setupRequired()
	if err != nil {
		return nil, "", err
	}
	if setupRequired {
		return nil, "", ErrSetupRequired
	}
	userID, dbUsername, passwordHash, err := s.store.GetAdminUserByUsername(strings.TrimSpace(username))
	if err != nil {
		if errors.Is(err, masterstate.ErrNotFound) {
			return nil, "", ErrUnauthorized
		}
		return nil, "", err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return nil, "", ErrUnauthorized
	}
	token, err := s.newSession(userID)
	if err != nil {
		return nil, "", err
	}
	return &models.AuthenticatedUser{ID: userID, Username: dbUsername}, token, nil
}

func (s *Service) Logout(token string) error {
	if token == "" {
		return nil
	}
	return s.store.DeleteAdminSession(token)
}

func (s *Service) Authenticate(token string) (*models.AuthenticatedUser, error) {
	if token == "" {
		return nil, ErrUnauthorized
	}
	userID, username, expiresAt, err := s.store.GetAdminSession(token)
	if err != nil {
		if errors.Is(err, masterstate.ErrNotFound) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	if time.Now().UTC().After(expiresAt) {
		_ = s.store.DeleteAdminSession(token)
		return nil, ErrUnauthorized
	}
	return &models.AuthenticatedUser{ID: userID, Username: username}, nil
}

func (s *Service) ChangePassword(userID int64, currentPassword, newPassword string) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	if currentPassword == newPassword {
		return fmt.Errorf("new password must be different from current password")
	}
	username, err := s.store.GetAdminUserByID(userID)
	if err != nil {
		if errors.Is(err, masterstate.ErrNotFound) {
			return ErrUnauthorized
		}
		return err
	}
	dbUserID, _, passwordHash, err := s.store.GetAdminUserByUsername(username)
	if err != nil {
		return err
	}
	if dbUserID != userID {
		return ErrUnauthorized
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(currentPassword)); err != nil {
		return ErrCurrentPasswordWrong
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.store.UpdateAdminPassword(userID, string(hash))
}

func (s *Service) setupRequired() (bool, error) {
	hasAdmin, err := s.store.HasAdminUsers()
	if err != nil {
		return false, err
	}
	return !hasAdmin, nil
}

func (s *Service) newSession(userID int64) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	expiresAt := time.Now().UTC().Add(s.sessionTTL)
	if err := s.store.CreateAdminSession(token, userID, expiresAt); err != nil {
		return "", err
	}
	return token, nil
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func validateCredentials(username, password string) error {
	username = strings.TrimSpace(username)
	if len(username) < 3 {
		return fmt.Errorf("username must be at least 3 characters")
	}
	return validatePassword(password)
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	return nil
}
