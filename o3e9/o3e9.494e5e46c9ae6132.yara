import "hash"

rule o3e9_494e5e46c9ae6132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.494e5e46c9ae6132"
     cluster="o3e9.494e5e46c9ae6132"
     cluster_size="2991 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="delf bancteian reconyc"
     md5_hashes="['263b44d75c9ac210ed14d3928cc6e79f', '2d462c50a9fa2e3d81d4887f9d13e89e', '1986bc2ff652320c44076e1c039cff15']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2648833,1109) == "8b3b244ae19867d0360498775f80ac63"
}

