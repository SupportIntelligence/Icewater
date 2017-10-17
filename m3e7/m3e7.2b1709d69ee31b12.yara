import "hash"

rule m3e7_2b1709d69ee31b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.2b1709d69ee31b12"
     cluster="m3e7.2b1709d69ee31b12"
     cluster_size="64 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="mira ahruw finj"
     md5_hashes="['ecbe81e1adee72bc92d386dca03991c8', '1b424e8ea142eb25f8f47ed5f3a9e758', '74c723b9a00eb50d481725d765ca7247']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(25648,1026) == "ab7c6fc100a1e0bc7b63d112574d5230"
}

