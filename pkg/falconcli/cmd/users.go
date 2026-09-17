// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"fmt"

	"github.com/dogukanturhal/falcon-id/pkg/falconcli/client"
	"github.com/spf13/cobra"
)

func newUsersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "users",
		Short: "Manage users",
		Long:  "Commands for listing, getting, creating, and deleting users in the Falcon ID platform",
	}
	cmd.AddCommand(newUsersListCmd())
	cmd.AddCommand(newUsersGetCmd())
	cmd.AddCommand(newUsersCreateCmd())
	cmd.AddCommand(newUsersDeleteCmd())
	return cmd
}

func newUsersListCmd() *cobra.Command {
	var page, pageSize int
	var search string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List users",
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := &client.ListOptions{Page: page, PageSize: pageSize, Search: search}
			resp, err := falconClient.ListUsers(cmd.Context(), opts)
			if err != nil {
				return err
			}

			headers := []string{"ID", "EMAIL", "USERNAME", "STATUS", "CREATED"}
			rows := make([][]string, len(resp.Users))
			for i, u := range resp.Users {
				rows[i] = []string{
					u.ID,
					u.Email,
					u.Username,
					printer.Badge(u.Status),
					u.CreatedAt.Format("2006-01-02"),
				}
			}
			return printer.Print(headers, rows, resp)
		},
	}
	cmd.Flags().IntVar(&page, "page", 1, "Page number")
	cmd.Flags().IntVar(&pageSize, "page-size", 20, "Items per page")
	cmd.Flags().StringVar(&search, "search", "", "Search filter")
	return cmd
}

func newUsersGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get [id]",
		Short: "Get user details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := falconClient.GetUser(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			headers := []string{"FIELD", "VALUE"}
			rows := [][]string{
				{"ID", resp.ID},
				{"Email", resp.Email},
				{"Username", resp.Username},
				{"Name", resp.FirstName + " " + resp.LastName},
				{"Status", printer.Badge(resp.Status)},
				{"Created", resp.CreatedAt.Format("2006-01-02 15:04:05")},
			}
			return printer.Print(headers, rows, resp)
		},
	}
}

func newUsersCreateCmd() *cobra.Command {
	var email, username, password, firstName, lastName string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new user",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resp, err := falconClient.CreateUser(cmd.Context(), &client.CreateUserRequest{
				Email:     email,
				Username:  username,
				Password:  password,
				FirstName: firstName,
				LastName:  lastName,
			})
			if err != nil {
				return err
			}
			printer.PrintSuccess(fmt.Sprintf("User created: %s (%s)", resp.Username, resp.ID))
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "Email address")
	cmd.Flags().StringVar(&username, "username", "", "Username")
	cmd.Flags().StringVar(&password, "password", "", "Password")
	cmd.Flags().StringVar(&firstName, "first-name", "", "First name")
	cmd.Flags().StringVar(&lastName, "last-name", "", "Last name")
	_ = cmd.MarkFlagRequired("email")
	_ = cmd.MarkFlagRequired("username")
	_ = cmd.MarkFlagRequired("password")
	return cmd
}

func newUsersDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [id]",
		Short: "Delete a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := falconClient.DeleteUser(cmd.Context(), args[0]); err != nil {
				return err
			}
			printer.PrintSuccess(fmt.Sprintf("User %s deleted", args[0]))
			return nil
		},
	}
}
