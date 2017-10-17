import "hash"

rule m3e9_1c1a91a1c2000922
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1c1a91a1c2000922"
     cluster="m3e9.1c1a91a1c2000922"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy androm backdoor"
     md5_hashes="['009dc74252fcd0fd87d3e73f0d5f1285', '009dc74252fcd0fd87d3e73f0d5f1285', '009dc74252fcd0fd87d3e73f0d5f1285']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(24576,1024) == "0dfc0e71a745ccacf205794e88ed4ec7"
}

