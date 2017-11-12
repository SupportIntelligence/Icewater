import "hash"

rule m3e9_49947841c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.49947841c8000b12"
     cluster="m3e9.49947841c8000b12"
     cluster_size="457 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['dfc3cd31e5b51f66e6e29f8fbc352fee', 'e6631c9945693153d94f703080a26ca1', '2cff9f13ea8a14f5e285753527ef6dd6']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(47104,1024) == "f7b221558b148f5f55ad23ea9cac0d8c"
}

