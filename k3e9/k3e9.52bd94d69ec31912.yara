import "hash"

rule k3e9_52bd94d69ec31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.52bd94d69ec31912"
     cluster="k3e9.52bd94d69ec31912"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['271914476cb94a0735f2e6fe5453853f', 'a03355236e0da1578a34ab365e158398', '055f4b32cfc11dcc52950d4a9dd6136f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,1024) == "177790c0127a5a5ab5ac5824b96ec385"
}

