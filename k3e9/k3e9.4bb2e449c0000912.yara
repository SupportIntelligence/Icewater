import "hash"

rule k3e9_4bb2e449c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4bb2e449c0000912"
     cluster="k3e9.4bb2e449c0000912"
     cluster_size="780 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zbot upatre trojandownloader"
     md5_hashes="['c25b4ba4ba5ff73bef830f4d26d6f56c', 'be1ac896d91e8d30c5b14c40a019d8f1', '3e10b64d60563697db4da2c70c044830']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9728,1024) == "1d88a6a07c2ac3c06ceaed9546447373"
}

