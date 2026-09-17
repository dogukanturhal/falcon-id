// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeUser(id, email, username, status string) User {
	return User{
		ID:        id,
		Email:     email,
		Username:  username,
		FirstName: "First",
		LastName:  "Last",
		Status:    status,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func TestListUsers_Success(t *testing.T) {
	users := []User{
		makeUser("u1", "alice@test.com", "alice", "active"),
		makeUser("u2", "bob@test.com", "bob", "inactive"),
	}
	listResp := UserListResponse{
		Users:      users,
		Total:      2,
		Page:       1,
		PageSize:   20,
		TotalPages: 1,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/users", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(listResp)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.ListUsers(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, resp.Users, 2)
	assert.Equal(t, 2, resp.Total)
	assert.Equal(t, "alice", resp.Users[0].Username)
}

func TestListUsers_WithOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "2", r.URL.Query().Get("page"))
		assert.Equal(t, "10", r.URL.Query().Get("page_size"))
		assert.Equal(t, "alice", r.URL.Query().Get("search"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(UserListResponse{})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	_, err := c.ListUsers(context.Background(), &ListOptions{Page: 2, PageSize: 10, Search: "alice"})
	require.NoError(t, err)
}

func TestListUsers_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "forbidden"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.ListUsers(context.Background(), nil)
	require.Error(t, err)
	assert.Nil(t, resp)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusForbidden, apiErr.StatusCode)
}

func TestGetUser_Success(t *testing.T) {
	user := makeUser("u-abc", "charlie@test.com", "charlie", "active")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/users/u-abc", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(UserResponse{User: user})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.GetUser(context.Background(), "u-abc")
	require.NoError(t, err)
	assert.Equal(t, "u-abc", resp.ID)
	assert.Equal(t, "charlie", resp.Username)
}

func TestGetUser_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "user not found"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.GetUser(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.Nil(t, resp)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)
}

func TestCreateUser_Success(t *testing.T) {
	createdUser := makeUser("new-1", "newuser@test.com", "newuser", "active")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/users", r.URL.Path)

		var req CreateUserRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "newuser@test.com", req.Email)
		assert.Equal(t, "newuser", req.Username)

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(UserResponse{User: createdUser})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.CreateUser(context.Background(), &CreateUserRequest{
		Email:     "newuser@test.com",
		Username:  "newuser",
		Password:  "secret123",
		FirstName: "New",
		LastName:  "User",
	})
	require.NoError(t, err)
	assert.Equal(t, "new-1", resp.ID)
	assert.Equal(t, "newuser", resp.Username)
}

func TestCreateUser_Conflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"code":    "USER_EXISTS",
			"message": "user with this email already exists",
		})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	resp, err := c.CreateUser(context.Background(), &CreateUserRequest{
		Email:    "existing@test.com",
		Username: "existing",
		Password: "pass",
	})
	require.Error(t, err)
	assert.Nil(t, resp)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusConflict, apiErr.StatusCode)
}

func TestDeleteUser_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/users/u-del-1", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	err := c.DeleteUser(context.Background(), "u-del-1")
	require.NoError(t, err)
}

func TestDeleteUser_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "user not found"})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	err := c.DeleteUser(context.Background(), "missing-id")
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)
}

func TestGetUser_PathEscape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Path should be properly escaped
		assert.Equal(t, "/api/v1/users/user%2Fwith%2Fslashes", r.URL.RawPath)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(UserResponse{})
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, "tok", "tenant")
	_, _ = c.GetUser(context.Background(), "user/with/slashes")
}
