# Monitor Implementation 

## Contents
- `types.go`: type declarations for monitor context and some basic monitor methods definitions
- `monitor.go`: implementation of clientside monitor functions that will be used by monitor_server in the server folder
- `monitor_process.go`: contains only process valid gossip object functions

## types.go
-`Monitor_context`: monitor context is an object that contains all the configuration and storage information about the monitor
- `methods`: internal methods defined in this file includes savestorage, loadstorage, getobject, isduplicate, and storeobject 
## monitor.go
- `Queryloggers`: send HTTP get request to loggers
- `QueryAuthorities`: send HTTP get request to CAs
- `Check_entity_pom`: check if there is a pom against the provided URL 
- `isLogger`: check if the entities is in the Loggers list from the public config file
- `IsAuthority`: check if the entities is in the CAs list from the public config file
- `Check_entity_pom`: check if there is a PoM aganist this entity 
- `AccuseEntity`: accuses the entity if its URL is provided   
- `Send_to_gossiper`: send the input gossip object to the gossiper  
- `PeriodicTasks` : query loggers once per MMD, accuse if the logger is inactive
