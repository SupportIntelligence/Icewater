import "hash"

rule o3e9_30d25a3b95c39b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.30d25a3b95c39b32"
     cluster="o3e9.30d25a3b95c39b32"
     cluster_size="8651 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     md5_hashes="['0b3cf325770a010b5a47aca2eaa77e3d', '0b15dbab21620b0b7b2d07bd95d19ca4', '0075e31a4504808955b92ab5e002c76e']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(41984,1024) == "74091addde581aac4f19b19e339c11e2"
}

