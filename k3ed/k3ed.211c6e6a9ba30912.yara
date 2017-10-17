import "hash"

rule k3ed_211c6e6a9ba30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.211c6e6a9ba30912"
     cluster="k3ed.211c6e6a9ba30912"
     cluster_size="151 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy malicious attribute"
     md5_hashes="['bdc3baa51451af102a65d54c2e84f53b', 'bc3fed496a8d8d7a8a04b1ab6dc3b60a', '3c6ee77667ffd4ff41b20741f569cfc4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(37376,1536) == "5431761c1cb6f24727936b62e5d9c0cd"
}

