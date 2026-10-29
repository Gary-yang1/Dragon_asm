package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

const activeAPIProjectEnsurePath = activeAPIPathPrefix + "/integrations/projects/ensure"

var (
	ErrEngineProjectSetup    = errors.New("主动引擎项目自动关联失败，请检查连接后重试")
	ErrEngineProjectPending  = errors.New("历史项目创建结果尚未确认，重试时将查询恢复；为避免重复项目，暂不重复创建")
	ErrEngineProjectAccess   = errors.New("主动引擎未授权项目自动关联，请在服务密钥设置中应用 ASM 接入配置，并确认服务账号拥有项目读取和创建权限")
	ErrEngineProjectProtocol = errors.New("主动引擎尚未提供幂等项目关联接口，请升级主动引擎后重试")
)

// engineProjectAPI keeps database orchestration independent of HTTP and signing.
type engineProjectAPI interface {
	projectEndpoint() string
	ensureManagedProject(context.Context, string, string, string) (managedActiveProject, error)
	findManagedProject(context.Context, string, string) (managedActiveProject, error)
}

type managedActiveProject struct {
	ID          int    `json:"id"`
	ExternalID  string `json:"external_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Created     bool   `json:"created"`
}

func (a *ActiveAPIEngineAdapter) projectEndpoint() string { return a.baseURL }

func (a *ActiveAPIEngineAdapter) ensureManagedProject(ctx context.Context, externalID, name, description string) (managedActiveProject, error) {
	body, _ := json.Marshal(struct {
		ExternalID  string `json:"external_id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}{externalID, name, description})
	resp, err := a.doSignedJSON(ctx, http.MethodPost, activeAPIProjectEnsurePath, body)
	if err != nil {
		return managedActiveProject{}, ErrEngineProjectSetup
	}
	var envelope activeAPIEnvelope[managedActiveProject]
	if err := decodeProjectResponse(resp, &envelope); err != nil {
		return managedActiveProject{}, err
	}
	if envelope.Code != http.StatusOK {
		return managedActiveProject{}, projectResponseError(envelope.Code)
	}
	// External identity, rather than mutable display names, determines ownership.
	if envelope.Data.ID <= 0 || envelope.Data.ExternalID != externalID {
		return managedActiveProject{}, ErrEngineProjectSetup
	}
	return envelope.Data, nil
}

// findManagedProject is only for recovery of historical non-idempotent requests.
func (a *ActiveAPIEngineAdapter) findManagedProject(ctx context.Context, name, description string) (managedActiveProject, error) {
	var found managedActiveProject
	for page := 1; page <= 10; page++ {
		path := activeAPIPathPrefix + "/projects?" + url.Values{"search": {name}, "page": {strconv.Itoa(page)}, "pageSize": {"100"}}.Encode()
		resp, err := a.doSignedJSON(ctx, http.MethodGet, path, nil)
		if err != nil {
			return managedActiveProject{}, ErrEngineProjectSetup
		}
		var envelope activeAPIEnvelope[struct {
			Projects []managedActiveProject `json:"projects"`
			Total    *int                   `json:"total"`
		}]
		if err := decodeProjectResponse(resp, &envelope); err != nil {
			return managedActiveProject{}, err
		}
		if envelope.Code != http.StatusOK {
			return managedActiveProject{}, projectResponseError(envelope.Code)
		}
		if envelope.Data.Total == nil || *envelope.Data.Total < 0 || envelope.Data.Projects == nil || len(envelope.Data.Projects) > 100 {
			return managedActiveProject{}, ErrEngineProjectSetup
		}
		for _, project := range envelope.Data.Projects {
			if project.Name != name {
				continue
			}
			if project.ID <= 0 || project.Description != description || found.ID != 0 {
				return managedActiveProject{}, ErrEngineProjectSetup
			}
			found = project
		}
		if *envelope.Data.Total <= page*100 {
			return found, nil
		}
	}
	return managedActiveProject{}, ErrEngineProjectSetup
}

func projectResponseError(status int) error {
	sentinel := ErrEngineProjectSetup
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		sentinel = ErrEngineProjectAccess
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		sentinel = ErrEngineProjectProtocol
	}
	return activeAPIResponseError(sentinel, status)
}

func decodeProjectResponse(resp *http.Response, out any) error {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return projectResponseError(resp.StatusCode)
	}
	return decodeActiveAPIJSON(resp.Body, out, ErrEngineProjectSetup)
}
