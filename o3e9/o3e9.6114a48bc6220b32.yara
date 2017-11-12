import "hash"

rule o3e9_6114a48bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.6114a48bc6220b32"
     cluster="o3e9.6114a48bc6220b32"
     cluster_size="23 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="lethic ayzg cryp"
     md5_hashes="['a09e7c739aa1b9ba6bae3fb76eceb603', 'a31d182569c8296d59c1a81655b637fa', 'b65c238abb1a1dc29fafbf2ce94cfa2d']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(88064,1024) == "e58389b3651a102ba06d539da1ff2f1e"
}

