package localauthority

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

type revokeCommand struct {
	authorityID string
	// TODO: add type for JWT or x509 (currently just default to JWT)
	printer cliprinter.Printer
	env     *commoncli.Env
}

func NewRevokeCommand() cli.Command {
	return NewRevokeCommandWithEnv(commoncli.DefaultEnv)
}

func NewRevokeCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &revokeCommand{env: env})
}

func (*revokeCommand) Name() string {
	return "localauthority revoke"
}

func (*revokeCommand) Synopsis() string {
	return "Revoke authority"
}

func (c *revokeCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	localauthorityClient := serverClient.NewLocalAuthorityClient()
	revokeResponse, err := localauthorityClient.RevokeJWTAuthority(ctx, &localauthorityv1.RevokeJWTAuthorityRequest{AuthorityId: c.authorityID})
	if err != nil {
		return err
	}

	return c.printer.PrintProto(revokeResponse)
}

func (c *revokeCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.authorityID, "authorityID", "", "An authority ID. For JWTs this is the key ID (kid).")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, c.prettyPrintRevoke)
}

func (c *revokeCommand) prettyPrintRevoke(env *commoncli.Env, results ...any) error {
	revokeResp, ok := results[0].(*localauthorityv1.RevokeJWTAuthorityResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}
	authorityID := string(revokeResp.RevokedAuthority.AuthorityId)
	msg := fmt.Sprintf("revoked JWT with authority ID %s", authorityID)
	env.Println(msg)

	return nil
}
