package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/events"
	runtime "github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/lambda"
)

var (
	Region    = os.Getenv("AWS_REGION")
	VPCID     = os.Getenv("VPCID")
	CGWMain   = os.Getenv("CGW_MAIN")
	CGWBackup = os.Getenv("CGW_BACKUP")
	// target CIDR block
	DestinationCidrBlock = os.Getenv("DESTINATION_CIDR_BLOCK")
)

const (
	StateOK               = "OK"
	StateAlarm            = "ALARM"
	StateInsufficientData = "INSUFFICIENT_DATA"
)

var lambdaClient = lambda.New(session.New())
var ec2Client = ec2.New(session.New())

type AlarmState struct {
	Value      string          `json:"value"`
	Reason     string          `json:"reason"`
	ReasonData json.RawMessage `json:"reasonData"`
	Timestamp  string          `json:"timestamp"`
}

type Detail struct {
	AlarmName     string     `json:"alarmName"`
	State         AlarmState `json:"state"`
	PreviousState AlarmState `json:"previousState"`
	// Configuration
}

func callLambda() (string, error) {
	input := &lambda.GetAccountSettingsInput{}
	req, resp := lambdaClient.GetAccountSettingsRequest(input)
	err := req.Send()
	output, _ := json.Marshal(resp.AccountUsage)
	return string(output), err
}

func vpnRouteTo(ctx context.Context, cgw string) error {
	rts := listRouteTables(ctx)
	for rt := range rts {
		log.Printf("checking for route table: %s", *rt.RouteTableId)
		isReplaced := false
		for _, route := range rt.Routes {
			if *route.DestinationCidrBlock != DestinationCidrBlock {
				log.Printf("ignore route: %s", *route.DestinationCidrBlock)
				continue
			}
			if route.NetworkInterfaceId != nil && *route.NetworkInterfaceId != cgw {
				if _, err := ec2Client.ReplaceRouteWithContext(ctx, &ec2.ReplaceRouteInput{
					RouteTableId:         rt.RouteTableId,
					DestinationCidrBlock: route.DestinationCidrBlock,
					NetworkInterfaceId:   aws.String(cgw),
				}); err != nil {
					log.Printf("replace route fail, err: %v", err)
					return err
				}
				isReplaced = true
				log.Printf("%s replace route to %s via %s", *rt.RouteTableId, DestinationCidrBlock, cgw)
			} else {
				log.Printf("route to %s via %s already", DestinationCidrBlock, cgw)
			}
		}
		if !isReplaced {
			if _, err := ec2Client.CreateRouteWithContext(ctx, &ec2.CreateRouteInput{
				RouteTableId:         rt.RouteTableId,
				DestinationCidrBlock: aws.String(DestinationCidrBlock),
				NetworkInterfaceId:   aws.String(cgw),
			}); err != nil {
				log.Printf("create route fail, err: %v", err)
				return err
			}
			log.Printf("%s create route to %s via %s", *rt.RouteTableId, DestinationCidrBlock, cgw)
		}
	}
	return nil
}

func handleRequest(ctx context.Context, event events.CloudWatchEvent) error {
	eventJson, _ := json.MarshalIndent(event, "", "  ")
	log.Printf("EVENT: %s", eventJson)
	log.Printf("REGION: %s", Region)
	detailRaw, err := event.Detail.MarshalJSON()
	if err != nil {
		return err
	}
	var detail Detail
	if err := json.Unmarshal(detailRaw, &detail); err != nil {
		return err
	}

	lc, _ := lambdacontext.FromContext(ctx)
	log.Printf("REQUEST ID: %s", lc.AwsRequestID)
	// global variable
	log.Printf("FUNCTION NAME: %s", lambdacontext.FunctionName)
	// context method
	deadline, _ := ctx.Deadline()
	log.Printf("DEADLINE: %s", deadline)

	// Make sure of routing to the stable CGW
	var targetCGW *string
	switch detail.State.Value {
	case StateAlarm:
		targetCGW, err = getNetworkInterfaceId(ctx, CGWBackup)
	case StateOK:
		targetCGW, err = getNetworkInterfaceId(ctx, CGWMain)
	default:
		log.Printf("cannot handle state: %s", detail.State.Value)
		return nil
	}
	if err != nil {
		return err
	}
	if err := vpnRouteTo(ctx, *targetCGW); err != nil {
		log.Printf("Error replace route to %s, %v", *targetCGW, err)
		return err
	}

	// AWS SDK call
	usage, err := callLambda()
	if err != nil {
		return err
	}
	log.Printf("USAGE: %s", usage)
	return nil
}

func getNetworkInterfaceId(ctx context.Context, publicIP string) (*string, error) {
	input := ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("association.public-ip"),
				Values: aws.StringSlice([]string{publicIP}),
			},
		},
	}
	output, err := ec2Client.DescribeNetworkInterfacesWithContext(ctx, &input)
	if err != nil {
		log.Printf("could not describe network interfaces with public ip: %s", publicIP)
		return nil, err
	}
	for _, ni := range output.NetworkInterfaces {
		return ni.NetworkInterfaceId, nil
	}
	return nil, fmt.Errorf("network interface not found by public ip: %s", publicIP)
}

func listRouteTables(ctx context.Context) <-chan *ec2.RouteTable {
	rt := make(chan *ec2.RouteTable)
	go func() {
		var nextToken *string
		defer close(rt)
		for {
			input := ec2.DescribeRouteTablesInput{
				NextToken: nextToken,
				Filters: []*ec2.Filter{
					{
						Name:   aws.String("vpc-id"),
						Values: aws.StringSlice([]string{VPCID}),
					},
				},
			}
			output, err := ec2Client.DescribeRouteTablesWithContext(ctx, &input)
			if err != nil {
				log.Printf("describe route tables fail, err: %v", err)
				return
			}
			for _, v := range output.RouteTables {
				rt <- v
			}
			if output.NextToken == nil {
				return
			}
			nextToken = output.NextToken
		}
	}()
	return rt
}

func main() {
	runtime.Start(handleRequest)
}
