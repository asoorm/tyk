package main

import (
	"net/http"

	"github.com/asoorm/serverless/provider"
	"github.com/asoorm/serverless/provider/aws"
	"github.com/asoorm/serverless/provider/azure"
	"github.com/pkg/errors"

	"github.com/TykTechnologies/tyk/apidef"
)

type Serverless struct {
	BaseMiddleware
}

func (k *Serverless) Name() string {
	return "Serverless"
}

func (k *Serverless) EnabledForSpec() bool {
	if !k.Spec.GlobalConfig.EnableServerless {
		return false
	}

	for _, v := range k.Spec.VersionData.Versions {
		if len(v.ExtendedPaths.Serverless) > 0 {
			return true
		}
	}

	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *Serverless) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	_, versionPaths, _, _ := k.Spec.Version(r)

	found, meta := k.Spec.CheckSpecMatchesStatus(r, versionPaths, InvokeServerlessFunction)
	if !found {
		return nil, http.StatusOK
	}

	vPathMeta := meta.(*apidef.ServerlessMeta)

	var p provider.Provider
	var err error
	switch vPathMeta.Provider {
	case "aws-lambda":
		p, err = aws.NewProvider()
		break
	case "azure-functions":
		p, err = azure.NewProvider()
		break
	default:
		return errors.New("unknown provider"), mwStatusRespond
	}

	if err != nil {
		return errors.Wrap(err, "unable to load provider"), mwStatusRespond
	}

	if err := p.Init(k.Spec.GlobalConfig.ServerlessProviderConfigs[vPathMeta.Provider]); err != nil {
		return errors.Wrap(err, "unable to init provider"), mwStatusRespond
	}

	function := provider.Function{
		Name:    vPathMeta.ProviderConfig["Name"].(string),
		Version: vPathMeta.ProviderConfig["Version"].(string),
	}
	res, err := p.Invoke(function, nil)
	if err != nil {
		return errors.Wrap(err, "unable to invoke function"), mwStatusRespond
	}

	w.WriteHeader(res.StatusCode)
	w.Write(res.Body)

	return nil, mwStatusRespond
}
