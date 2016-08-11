curl -XDELETE "[endpoint]/cw*"
curl -XPUT "[endpoint]/_template/cw-*" --data @cw_template.json
curl -XPUT "[endpoint]/_template/cwl-*" --data @cwl_template.json
curl -GET "[endpoint]/_aliases?pretty=1"