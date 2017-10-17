import "hash"

rule n3ec_4a9da849c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.4a9da849c0000b32"
     cluster="n3ec.4a9da849c0000b32"
     cluster_size="2291 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="browsefox kranet unwanted"
     md5_hashes="['2ed6a91df5f67bf65aa3963f0b3b263f', '44462164575eca449e26def859ce4eaa', '30ae3c656b19d8d65a2d0c5f1619d990']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(274432,1536) == "a23f62b767b4ef51cee21c493e7fe22e"
}

