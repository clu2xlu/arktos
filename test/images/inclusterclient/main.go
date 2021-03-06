/*
Copyright 2019 The Kubernetes Authors.
Copyright 2020 Authors of Arktos - file modified.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/logs"
	"k8s.io/klog"
)

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	pollInterval := flag.Int("poll-interval", 30, "poll interval of call to /healhtz in seconds")
	flag.Set("logtostderr", "true")
	flag.Parse()

	klog.Infof("started")

	cfgs, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("err: %v", err)
	}

	kubeConfig := cfgs.GetConfig()
	kubeConfig.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return &debugRt{
			rt: rt,
		}
	})

	c := kubernetes.NewForConfigOrDie(cfgs).RESTClient()

	t := time.Tick(time.Duration(*pollInterval) * time.Second)
	for {
		<-t
		klog.Infof("calling /healthz")
		b, err := c.Get().AbsPath("/healthz").Do().Raw()
		if err != nil {
			klog.Errorf("status=failed")
			klog.Errorf("error checking /healthz: %v\n%s\n", err, string(b))
		}
	}
}

type debugRt struct {
	rt http.RoundTripper
}

func (rt *debugRt) RoundTrip(req *http.Request) (*http.Response, error) {
	authHeader := req.Header.Get("Authorization")
	if len(authHeader) != 0 {
		authHash := sha256.Sum256([]byte(fmt.Sprintf("%s|%s", "salt", authHeader)))
		klog.Infof("authz_header=%s", base64.RawURLEncoding.EncodeToString(authHash[:]))
	} else {
		klog.Errorf("authz_header=<empty>")
	}
	return rt.rt.RoundTrip(req)
}

func (rt *debugRt) WrappedRoundTripper() http.RoundTripper { return rt.rt }
