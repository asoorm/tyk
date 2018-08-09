package main

import (
	"io/ioutil"
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
	var c provider.Conf
	var err error
	switch vPathMeta.Provider {
	case "aws-lambda":
		p, err = aws.NewProvider()
		c = aws.Conf{
			Region: vPathMeta.ProviderConfig["Region"].(string),
		}
		break
	case "azure-functions":
		p, err = azure.NewProvider()
		c = azure.Conf{}
		break
	default:
		log.Errorf("serverless misconfigured, unknown provider %s", vPathMeta.Provider)
		return errors.New("unknown provider"), http.StatusInternalServerError
	}
	if err != nil {
		return errors.Wrap(err, "unable to load provider"), http.StatusInternalServerError
	}

	if err := p.Init(c); err != nil {
		return errors.Wrap(err, "unable to init provider"), http.StatusInternalServerError
	}

	function := provider.Function{
		Name:    vPathMeta.ProviderConfig["Name"].(string),
		Version: vPathMeta.ProviderConfig["Version"].(string),
	}

	bodyCloser := copyBody(r.Body)
	body, err := ioutil.ReadAll(bodyCloser)
	if err != nil {
		return errors.Wrap(err, "unable to read request body"), http.StatusInternalServerError
	}

	res, err := p.Invoke(function, body)
	if err != nil {
		return errors.Wrap(err, "unable to invoke function"), http.StatusInternalServerError
	}

	w.WriteHeader(res.StatusCode)
	w.Write(res.Body)

	return nil, mwStatusRespond
}
