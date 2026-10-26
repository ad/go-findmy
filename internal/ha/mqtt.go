package ha

import (
	"fmt"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type Client struct {
	c mqtt.Client
}

func Dial(broker, user, password string) (*Client, error) {
	opts := mqtt.NewClientOptions().
		AddBroker(broker).
		SetClientID("go-findmy").
		SetUsername(user).
		SetPassword(password).
		SetWill(AvailabilityTopic, "offline", 1, true).
		SetConnectRetry(true).
		SetOnConnectHandler(func(c mqtt.Client) {
			c.Publish(AvailabilityTopic, 1, true, "online")
		})
	c := mqtt.NewClient(opts)
	t := c.Connect()
	t.Wait()
	if err := t.Error(); err != nil {
		return nil, fmt.Errorf("mqtt: %w", err)
	}
	return &Client{c}, nil
}

func (c *Client) Publish(topic string, payload []byte) error {
	t := c.c.Publish(topic, 1, true, payload)
	if !t.WaitTimeout(30 * time.Second) {
		return fmt.Errorf("mqtt: publish %s timed out", topic)
	}
	return t.Error()
}

func (c *Client) Close() {
	c.c.Publish(AvailabilityTopic, 1, true, "offline").WaitTimeout(5 * time.Second)
	c.c.Disconnect(1000)
}
