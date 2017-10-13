import "hash"

rule k3e9_6b66d36b9a4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b66d36b9a4b5912"
     cluster="k3e9.6b66d36b9a4b5912"
     cluster_size="15 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['c7354a2bf4a888e33369238f3c4964de', 'd52189381ba813293e77027bc56b35b1', 'c7354a2bf4a888e33369238f3c4964de']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9288,1036) == "2a5ed0a6e568c6168dc9cdc440a1598c"
}

