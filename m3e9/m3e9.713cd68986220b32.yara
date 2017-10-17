import "hash"

rule m3e9_713cd68986220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.713cd68986220b32"
     cluster="m3e9.713cd68986220b32"
     cluster_size="91 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['e30644a56abd1724329dae1ecbf99c96', 'ca2477a809b4c34a27ad12bc77b7d893', 'df3f9a84fbd0236929f3aa00e1f85e3c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(40960,1024) == "645e2a6a8f6cf9fe1336efdc5240aad2"
}

