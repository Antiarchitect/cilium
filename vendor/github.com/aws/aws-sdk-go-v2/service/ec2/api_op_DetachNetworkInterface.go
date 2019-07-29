// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package ec2

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
	"github.com/aws/aws-sdk-go-v2/private/protocol"
	"github.com/aws/aws-sdk-go-v2/private/protocol/ec2query"
)

// Contains the parameters for DetachNetworkInterface.
type DetachNetworkInterfaceInput struct {
	_ struct{} `type:"structure"`

	// The ID of the attachment.
	//
	// AttachmentId is a required field
	AttachmentId *string `locationName:"attachmentId" type:"string" required:"true"`

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have
	// the required permissions, the error response is DryRunOperation. Otherwise,
	// it is UnauthorizedOperation.
	DryRun *bool `locationName:"dryRun" type:"boolean"`

	// Specifies whether to force a detachment.
	//
	//    * Use the Force parameter only as a last resort to detach a network interface
	//    from a failed instance.
	//
	//    * If you use the Force parameter to detach a network interface, you might
	//    not be able to attach a different network interface to the same index
	//    on the instance without first stopping and starting the instance.
	//
	//    * If you force the detachment of a network interface, the instance metadata
	//    (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
	//    might not get updated. This means that the attributes associated with
	//    the detached network interface might still be visible. The instance metadata
	//    will get updated when you stop and start the instance.
	Force *bool `locationName:"force" type:"boolean"`
}

// String returns the string representation
func (s DetachNetworkInterfaceInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *DetachNetworkInterfaceInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "DetachNetworkInterfaceInput"}

	if s.AttachmentId == nil {
		invalidParams.Add(aws.NewErrParamRequired("AttachmentId"))
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

type DetachNetworkInterfaceOutput struct {
	_ struct{} `type:"structure"`
}

// String returns the string representation
func (s DetachNetworkInterfaceOutput) String() string {
	return awsutil.Prettify(s)
}

const opDetachNetworkInterface = "DetachNetworkInterface"

// DetachNetworkInterfaceRequest returns a request value for making API operation for
// Amazon Elastic Compute Cloud.
//
// Detaches a network interface from an instance.
//
//    // Example sending a request using DetachNetworkInterfaceRequest.
//    req := client.DetachNetworkInterfaceRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
//
// Please also see https://docs.aws.amazon.com/goto/WebAPI/ec2-2016-11-15/DetachNetworkInterface
func (c *Client) DetachNetworkInterfaceRequest(input *DetachNetworkInterfaceInput) DetachNetworkInterfaceRequest {
	op := &aws.Operation{
		Name:       opDetachNetworkInterface,
		HTTPMethod: "POST",
		HTTPPath:   "/",
	}

	if input == nil {
		input = &DetachNetworkInterfaceInput{}
	}

	req := c.newRequest(op, input, &DetachNetworkInterfaceOutput{})
	req.Handlers.Unmarshal.Remove(ec2query.UnmarshalHandler)
	req.Handlers.Unmarshal.PushBackNamed(protocol.UnmarshalDiscardBodyHandler)
	return DetachNetworkInterfaceRequest{Request: req, Input: input, Copy: c.DetachNetworkInterfaceRequest}
}

// DetachNetworkInterfaceRequest is the request type for the
// DetachNetworkInterface API operation.
type DetachNetworkInterfaceRequest struct {
	*aws.Request
	Input *DetachNetworkInterfaceInput
	Copy  func(*DetachNetworkInterfaceInput) DetachNetworkInterfaceRequest
}

// Send marshals and sends the DetachNetworkInterface API request.
func (r DetachNetworkInterfaceRequest) Send(ctx context.Context) (*DetachNetworkInterfaceResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &DetachNetworkInterfaceResponse{
		DetachNetworkInterfaceOutput: r.Request.Data.(*DetachNetworkInterfaceOutput),
		response:                     &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// DetachNetworkInterfaceResponse is the response type for the
// DetachNetworkInterface API operation.
type DetachNetworkInterfaceResponse struct {
	*DetachNetworkInterfaceOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// DetachNetworkInterface request.
func (r *DetachNetworkInterfaceResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}
