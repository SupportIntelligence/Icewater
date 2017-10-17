import "hash"

rule n3e9_49982ccbc6620b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.49982ccbc6620b16"
     cluster="n3e9.49982ccbc6620b16"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe malicious"
     md5_hashes="['b970af603e9d68b59b8464de34748d9b', '65d2629218e7e1ebdf29895088bb2aac', 'b970af603e9d68b59b8464de34748d9b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(108544,1024) == "9650727afb29740793894269db598dc4"
}

