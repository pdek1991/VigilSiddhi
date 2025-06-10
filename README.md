## Create index with post
```
curl -X PUT "http://192.168.56.30:9200/ird_trend" -H "Content-Type: application/json" -d "{\"mappings\":{\"properties\":{\"@timestamp\":{\"type\":\"date\"},\"system_id\":{\"type\":\"integer\"},\"channel_name\":{\"type\":\"text\"},\"cn_margin\":{\"type\":\"float\"},\"signal_level\":{\"type\":\"float\"},\"input_rate\":{\"type\":\"long\"}}}}"


curl -X PUT "http://192.168.56.30:9200/channel_config" -H "Content-Type: application/json" -d "{\"mappings\":{\"properties\":{\"channel_id\":{\"type\":\"integer\"},\"devices\":{\"type\":\"nested\",\"properties\":{\"id\":{\"type\":\"keyword\"},\"ip\":{\"type\":\"ip\"},\"username\":{\"type\":\"keyword\"},\"password\":{\"type\":\"keyword\"}}}}}}"


curl -X PUT "http://192.168.56.30:9200/global_config" -H "Content-Type: application/json" -d "{\"mappings\":{\"properties\":{\"id\":{\"type\":\"keyword\"},\"name\":{\"type\":\"text\"},\"type\":{\"type\":\"keyword\"},\"additional_ips\":{\"type\":\"nested\",\"properties\":{\"ip\":{\"type\":\"ip\"},\"username\":{\"type\":\"keyword\"},\"password\":{\"type\":\"keyword\"}}}}}}"


curl -X PUT "http://192.168.56.30:9200/windows_config" -H "Content-Type: application/json" -d "{\"mappings\":{\"properties\":{\"name\":{\"type\":\"keyword\"},\"ip\":{\"type\":\"ip\"},\"username\":{\"type\":\"keyword\"},\"password\":{\"type\":\"keyword\"},\"services\":{\"type\":\"keyword\"},\"processes\":{\"type\":\"keyword\"}}}}"


curl -X PUT "http://192.168.56.30:9200/ird_config" -H "Content-Type: application/json" -d "{\"mappings\":{\"properties\":{\"system_id\":{\"type\":\"keyword\"},\"ip_address\":{\"type\":\"ip\"},\"username\":{\"type\":\"keyword\"},\"password\":{\"type\":\"keyword\"},\"channel_name\":{\"type\":\"text\"}}}}"


curl -X PUT "http://192.168.56.30:9200/active_alarms" -H "Content-Type: application/json" -d "{\"mappings\":{\"properties\":{\"@timestamp\":{\"type\":\"date\"},\"alarm_id\":{\"type\":\"keyword\"},\"source\":{\"type\":\"keyword\"},\"server_ip\":{\"type\":\"ip\"},\"message\":{\"type\":\"text\"},\"severity\":{\"type\":\"keyword\"},\"channel_name\":{\"type\":\"keyword\"},\"device_name\":{\"type\":\"keyword\"},\"group_id\":{\"type\":\"keyword\"}}}}"


curl -X PUT "http://192.168.56.30:9200/historical_alarms" -H "Content-Type: application/json" -d "{\"mappings\":{\"properties\":{\"@timestamp\":{\"type\":\"date\"},\"alarm_id\":{\"type\":\"keyword\"},\"source\":{\"type\":\"keyword\"},\"server_ip\":{\"type\":\"ip\"},\"message\":{\"type\":\"text\"},\"severity\":{\"type\":\"keyword\"},\"channel_name\":{\"type\":\"keyword\"},\"device_name\":{\"type\":\"keyword\"},\"group_id\":{\"type\":\"keyword\"}}}}"
```

#Get index schema 
```
curl -X GET "http://192.168.56.30:9200/historical_alarms?pretty"
```

#Get index document

```curl -X GET "http://192.168.56.30:9200/active_alarms/_search?pretty"```