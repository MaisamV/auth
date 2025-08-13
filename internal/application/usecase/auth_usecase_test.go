package usecase_test

import (
	"context"
	"github.com/auth-service/internal/application/usecase"
	"github.com/auth-service/internal/domain/entity"
	"github.com/auth-service/internal/domain/vo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

// Mock implementations for testing
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Save(ctx context.Context, user *entity.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) FindByID(ctx context.Context, id string) (*entity.User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email vo.Email) (*entity.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUserRepository) ExistsByEmail(ctx context.Context, email vo.Email) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) UpdatePassword(ctx context.Context, id string, hashedPassword string) error {
	args := m.Called(ctx, id, hashedPassword)
	return args.Error(0)
}

type MockHashingService struct {
	mock.Mock
}

func (m *MockHashingService) Hash(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockHashingService) Verify(password, hash string) error {
	args := m.Called(password, hash)
	return args.Error(0)
}

type MockIDGeneratorService struct {
	mock.Mock
}

func (m *MockIDGeneratorService) GenerateID() string {
	args := m.Called()
	return args.String(0)
}

func TestAuthUseCase_RegisterUser(t *testing.T) {
	// Arrange
	mockUserRepo := new(MockUserRepository)
	mockHashingService := new(MockHashingService)
	mockIDGenerator := new(MockIDGeneratorService)

	authUseCase := usecase.NewAuthUseCase(
		mockUserRepo,
		nil, // clientRepo not needed for this test
		nil, // authCodeRepo not needed for this test
		nil, // refreshTokenRepo not needed for this test
		nil, // sessionRefreshTokenRepo not needed for this test
		nil, // blacklistRepo not needed for this test
		mockHashingService,
		nil, // tokenService not needed for this test
		nil, // pkceService not needed for this test
		mockIDGenerator,
	)

	req := usecase.RegisterUserRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	email, _ := vo.NewEmail(req.Email)

	// Set up mocks
	mockUserRepo.On("ExistsByEmail", mock.Anything, email).Return(false, nil)
	mockHashingService.On("Hash", req.Password).Return("hashed_password", nil)
	mockIDGenerator.On("GenerateID").Return("user_123")
	mockUserRepo.On("Save", mock.Anything, mock.AnythingOfType("*entity.User")).Return(nil)

	// Act
	resp, err := authUseCase.RegisterUser(context.Background(), req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "user_123", resp.UserID)
	assert.Equal(t, "test@example.com", resp.Email)

	// Verify all expectations were met
	mockUserRepo.AssertExpectations(t)
	mockHashingService.AssertExpectations(t)
	mockIDGenerator.AssertExpectations(t)
}

func TestAuthUseCase_RegisterUser_EmailAlreadyExists(t *testing.T) {
	// Arrange
	mockUserRepo := new(MockUserRepository)
	mockHashingService := new(MockHashingService)
	mockIDGenerator := new(MockIDGeneratorService)

	authUseCase := usecase.NewAuthUseCase(
		mockUserRepo,
		nil, nil, nil, nil, nil,
		mockHashingService,
		nil, nil,
		mockIDGenerator,
	)

	req := usecase.RegisterUserRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	email, _ := vo.NewEmail(req.Email)

	// Set up mocks - user already exists
	mockUserRepo.On("ExistsByEmail", mock.Anything, email).Return(true, nil)

	// Act
	resp, err := authUseCase.RegisterUser(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "already exists")

	// Verify expectations
	mockUserRepo.AssertExpectations(t)
}

func TestAuthUseCase_RegisterUser_InvalidEmail(t *testing.T) {
	// Arrange
	mockUserRepo := new(MockUserRepository)
	mockHashingService := new(MockHashingService)
	mockIDGenerator := new(MockIDGeneratorService)

	authUseCase := usecase.NewAuthUseCase(
		mockUserRepo,
		nil, nil, nil, nil, nil,
		mockHashingService,
		nil, nil,
		mockIDGenerator,
	)

	req := usecase.RegisterUserRequest{
		Email:    "invalid-email",
		Password: "password123",
	}

	// Act
	resp, err := authUseCase.RegisterUser(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid email")
}
