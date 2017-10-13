import "hash"

rule m3e9_41a497a898926f92
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.41a497a898926f92"
     cluster="m3e9.41a497a898926f92"
     cluster_size="374 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="shiz backdoor injector"
     md5_hashes="['bdcf67f61bbc9a8e411ea99fd980e887', 'afe6a2e4a27f524aa9b8e8ac8f73d493', '5c4f2a8d6aae4f665362123a761868df']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(29696,1024) == "aa620d7a61e420204f48371a9cbf9ab2"
}

