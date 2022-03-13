package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
)

func TestMain(t *testing.T) {
	d := time.Now().Add(50 * time.Millisecond)
	os.Setenv("AWS_LAMBDA_FUNCTION_NAME", "vpn-guard")
	ctx, cancel := context.WithDeadline(context.Background(), d)
	defer cancel()
	ctx = lambdacontext.NewContext(ctx, &lambdacontext.LambdaContext{
		AwsRequestID:       "495b12a8-xmpl-4eca-8168-12345678910b",
		InvokedFunctionArn: "arn:aws:lambda:ap-southeast-1:123456789012:function:vpn-guard",
	})
	inputJson := ReadJSONFromFile(t, "../event.json")
	var event events.CloudWatchEvent
	err := json.Unmarshal(inputJson, &event)
	if err != nil {
		t.Errorf("could not unmarshal event. error: %v", err)
	}
	err = handleRequest(ctx, event)
	if err != nil {
		t.Log(err)
	}
}

func ReadJSONFromFile(t *testing.T, inputFile string) []byte {
	inputJSON, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Errorf("could not open event test file. error: %v", err)
	}

	return inputJSON
}
