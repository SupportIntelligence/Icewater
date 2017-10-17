import "hash"

rule k3e9_6946fa7b61266796
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6946fa7b61266796"
     cluster="k3e9.6946fa7b61266796"
     cluster_size="36 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a71888c6ff93350ef7bec60287563dd4', '72658d6e94b5790d72d4dd07683a1474', '5dae8193bedb56a81ba48927dbc4f39a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18723,1041) == "f56d85d5e204fe8b22ff7546c043c8f3"
}

