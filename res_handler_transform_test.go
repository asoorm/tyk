package main

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

func TestTransformResponseWithURLRewrite(t *testing.T) {
	transformResponseConf := apidef.TemplateMeta{
		Path:   "get",
		Method: "GET",
		TemplateData: apidef.TemplateData{
			Mode:           "blob",
			TemplateSource: base64.StdEncoding.EncodeToString([]byte(`{"http_method":"{{.Method}}"}`)),
		},
	}

	urlRewriteConf := apidef.URLRewriteMeta{
		Path:         "abc",
		Method:       "GET",
		MatchPattern: "abc",
		RewriteTo:    "get",
	}

	responseProcessorConf := []apidef.ResponseProcessor{{Name: "response_body_transform"}}

	t.Run("Transform without rewrite", func(t *testing.T) {
		ts := newTykTestServer()
		defer ts.Close()

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.ResponseProcessors = responseProcessorConf
			updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
			})
		})

		ts.Run(t, test.TestCase{
			Path: "/get", Code: 200, BodyMatch: `{"http_method":"GET"}`,
		})
	})

	t.Run("Transform path equals rewrite to ", func(t *testing.T) {
		ts := newTykTestServer()
		defer ts.Close()

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.ResponseProcessors = responseProcessorConf

			updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
				v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{urlRewriteConf}
			})
		})

		ts.Run(t, test.TestCase{
			Path: "/get", Code: 200, BodyMatch: `{"http_method":"GET"}`,
		})
	})

	t.Run("Transform path equals rewrite path", func(t *testing.T) {
		ts := newTykTestServer()
		defer ts.Close()

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.ResponseProcessors = responseProcessorConf

			transformResponseConf.Path = "abc"

			updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.TransformResponse = []apidef.TemplateMeta{transformResponseConf}
				v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{urlRewriteConf}
			})
		})

		ts.Run(t, test.TestCase{
			Path: "/abc", Code: 200, BodyMatch: `{"http_method":"GET"}`,
		})
	})
}

const xmlMockBody = `
<?xml version='1.0' encoding='us-ascii'?>

<!--  A SAMPLE set of slides  -->

<slideshow 
    title="Sample Slide Show"
    date="Date of publication"
    author="Yours Truly"
    >

    <!-- TITLE SLIDE -->
    <slide type="all">
      <title>Wake up to WonderWidgets!</title>
    </slide>

    <!-- OVERVIEW -->
    <slide type="all">
        <title>Overview</title>
        <item>Why <em>WonderWidgets</em> are great</item>
        <item/>
        <item>Who <em>buys</em> WonderWidgets</item>
    </slide>

</slideshow>`

func TestResponseTranformMiddleware_rewriteMockResponse(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	specs := []func(spec *APISpec){
		// mock reply API
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/mock"
			spec.UseKeylessAccess = true
			spec.VersionData.NotVersioned = true
			spec.VersionData.Versions["Default"] = apidef.VersionInfo{
				Name:             "xml",
				UseExtendedPaths: true,
				ExtendedPaths: apidef.ExtendedPathsSet{
					WhiteList: []apidef.EndPointMeta{
						{
							Path: "/xml",
							MethodActions: map[string]apidef.EndpointMethodMeta{
								http.MethodGet: {
									Action: apidef.Reply,
									Code:   http.StatusOK,
									Data:   xmlMockBody,
								},
							},
						},
					},
				},
			}
		},
		func(spec *APISpec) {
			spec.Proxy.TargetURL = ts.URL + "/mock"
			spec.Proxy.ListenPath = "/transform"
			spec.UseKeylessAccess = true
			spec.VersionData.NotVersioned = true
			spec.VersionData.Versions["Default"] = apidef.VersionInfo{
				Name:             "Default",
				UseExtendedPaths: true,
				ExtendedPaths: apidef.ExtendedPathsSet{
					WhiteList: []apidef.EndPointMeta{
						{
							Path: "/xml",
						},
					},
					TransformResponse: []apidef.TemplateMeta{
						{
							Method: http.MethodPost,
							Path:   "/xml",
							TemplateData: apidef.TemplateData{
								Input:          "xml",
								Mode:           "blob",
								TemplateSource: `e3sgLiB8IGpzb25NYXJzaGFsIH19`,
							},
						},
					},
				},
			}
		},
	}

	for _, spec := range specs {
		buildAndLoadAPI(spec)
	}

	ts.Run(t, []test.TestCase{
		{Method: http.MethodGet, Path: "/mock/xml", Code: http.StatusOK, BodyMatch: xmlMockBody},
	}...)
}
