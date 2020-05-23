package internal

import (
	"fmt"
	"sync"

	"github.com/jingweno/upterm/host/api"
)

func NewClientRepo() *ClientRepo {
	return &ClientRepo{}
}

type ClientRepo struct {
	clients sync.Map
}

func (c *ClientRepo) Add(client api.Client) error {
	_, loaded := c.clients.LoadOrStore(client.Id, client)
	if loaded {
		return fmt.Errorf("client already exists")
	}

	return nil
}

func (c *ClientRepo) Delete(clientId string) {
	c.clients.Delete(clientId)
}

func (c *ClientRepo) Clients() []*api.Client {
	var clients []*api.Client

	c.clients.Range(func(key, value interface{}) bool {
		cc := value.(api.Client)
		clients = append(clients, &cc)
		return true
	})

	return clients
}
