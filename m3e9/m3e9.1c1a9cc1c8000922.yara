import "hash"

rule m3e9_1c1a9cc1c8000922
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1c1a9cc1c8000922"
     cluster="m3e9.1c1a9cc1c8000922"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy androm backdoor"
     md5_hashes="['cdc9be56d446eb2342cc7c2506c0756a', 'bb98040bea53e2c60140e97bcd1049e0', '23547d2c159e0fc7f51cd04f004654c7']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(20480,1024) == "13d3268c5c0285305299536cda4475aa"
}

