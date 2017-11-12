import "hash"

rule m3e9_691697a9c2000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.691697a9c2000912"
     cluster="m3e9.691697a9c2000912"
     cluster_size="2129 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['22d7222d592be255f3a37498c4f7015e', '02a99ccfd75a0b4236e6e6b919669d3b', '21500f76974d67e8144f2b24a505272b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(15360,1024) == "b469f0a139e038b7a04b7aeb5167900b"
}

