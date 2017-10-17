import "hash"

rule n3e9_29c60358d982e313
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c60358d982e313"
     cluster="n3e9.29c60358d982e313"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor malicious cuegoe"
     md5_hashes="['aa32bc7aececb467a887843dea1b5ce7', '621cc87f3cac9df0a1a36556b3655010', '32e2209bdae627a9f7b92dd5ca983f3f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(5136,1028) == "1ebf251d64af3760403e40a9f3e8a108"
}

