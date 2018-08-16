package main

import (
	"io/ioutil"
	"net/http"

	"github.com/asoorm/serverless/provider"
	"github.com/asoorm/serverless/provider/aws"
	"github.com/asoorm/serverless/provider/azure"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"

	"github.com/TykTechnologies/tyk/config"

	"github.com/TykTechnologies/tyk/apidef"
)

type Serverless struct {
	BaseMiddleware
	ServerlessConfigs map[string]interface{}
	Configs           map[string]provider.Conf
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

			k.ServerlessConfigs = config.Global().ServerlessProviderConfigs

			k.Configs = make(map[string]provider.Conf, len(config.Global().ServerlessProviderConfigs))

			for key, value := range config.Global().ServerlessProviderConfigs {
				switch key {
				case "aws-lambda":
					var cfg aws.Conf
					err := mapstructure.Decode(value, &cfg)
					if err != nil {
						return false
					}
					k.Configs[key] = cfg
				case "azure-functions":
					var cfg azure.Conf
					err := mapstructure.Decode(value, &cfg)
					if err != nil {
						return false
					}
					k.Configs[key] = cfg
				}
			}
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
		awsConfMap, ok := k.ServerlessConfigs[vPathMeta.Provider]
		if !ok {
			return errors.New("missing lambda configs"), http.StatusInternalServerError
		}
		awsConf := aws.Conf{}

		err := mapstructure.Decode(awsConfMap, &awsConf)
		if err != nil {
			return errors.New("unable to decode configs"), http.StatusInternalServerError
		}

		log.Printf("awsConf: %#v\n", awsConf)

		p, err = aws.NewProvider()
		if err != nil {
			return errors.New("unable to create provider"), http.StatusInternalServerError
		}

		if pathRegion, ok := vPathMeta.ProviderConfig["Region"].(string); ok {
			log.Warn("overriding region")
			awsConf.Region = pathRegion
		}

		c = awsConf
	case "azure-functions":
		p, err = azure.NewProvider()
		c = azure.Conf{}
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
