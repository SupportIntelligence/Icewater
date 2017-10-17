import "hash"

rule m3e9_40d2f949c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.40d2f949c0000912"
     cluster="m3e9.40d2f949c0000912"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['33a7dd827af23fe319e9e8ea797c3ca4', '391c0cb7157d8b7af4e679b905206349', 'a98f5521ece69a51862d1ab97da8a0ae']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(25600,1024) == "713e4276650b186ba5ad3c0618a74ed9"
}

