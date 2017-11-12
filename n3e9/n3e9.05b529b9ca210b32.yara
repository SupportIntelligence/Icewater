import "hash"

rule n3e9_05b529b9ca210b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.05b529b9ca210b32"
     cluster="n3e9.05b529b9ca210b32"
     cluster_size="2481 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="renamer delf grenam"
     md5_hashes="['4017e6ef00c4c31c174f5ea8249650ac', '3bc2e4578552c0ce945b249be87111e1', '1632a362dd3b5b260651a606b7401da2']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(463929,1081) == "87a736d096dd8f6c5aae9a67e116e67e"
}

