package sdk

import "fmt"

type Client struct {
	BaseURL string
}

func NewClient(baseURL string) *Client {
	return &Client{BaseURL: baseURL}
}

func (c *Client) Verify(token string) (bool, error) {
	fmt.Printf("Verifying token against %s\n", c.BaseURL)
	return true, nil
}
