import "hash"

rule k3e9_391c16b8dc92d331
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391c16b8dc92d331"
     cluster="k3e9.391c16b8dc92d331"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['683db4fbc63b1edb9397944797b6ccb2', '21ad6fcb7ebebc891406b30145854a2f', '21ad6fcb7ebebc891406b30145854a2f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15872,1024) == "4dd5f3b32f0b04add96a51354fe6e134"
}

