package storage

import (
	"github.com/go-redis/redis"
)

type RedisClient interface {
	redis.UniversalClient
}

type RedisOptions struct {
	*redis.UniversalOptions
}

// NewRedisClient returns a new multi client. The type of client returned depends
// on the following three conditions:
//
// 1. if a MasterName is passed a sentinel-backed FailoverClient will be returned
// 2. if the number of Addrs is two or more, a ClusterClient will be returned
// 3. otherwise, a single-node redis Client will be returned.
func NewRedisClient(opts *RedisOptions) (RedisClient, error) {
	client := redis.NewUniversalClient(opts.UniversalOptions)

	_, err := client.Ping().Result()
	if err != nil {
		return nil, err
	}

	return client, nil

	//switch clientType {
	//case sentinelClient:
	//	optionsStruct := &redis.FailoverOptions{}
	//	if err := mapstructure.Decode(&optionsStruct, opts); err != nil {
	//		return configError(err)
	//	}
	//	client = redis.NewFailoverClient(optionsStruct)
	//	break
	//case clusterClient:
	//	optionsStruct := &redis.ClusterOptions{}
	//	if err := mapstructure.Decode(&optionsStruct, opts); err != nil {
	//		return configError(err)
	//	}
	//	client = redis.NewClusterClient(optionsStruct)
	//	break
	//case defaultClient:
	//default:
	//	optionsStruct := &redis.UniversalOptions{}
	//	if err := mapstructure.Decode(&optionsStruct, opts); err != nil {
	//		return configError(err)
	//	}
	//	client = redis.NewClient(optionsStruct)
	//}
}


