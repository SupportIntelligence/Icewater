import "hash"

rule m3ed_4b958d1f649646d2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4b958d1f649646d2"
     cluster="m3ed.4b958d1f649646d2"
     cluster_size="40 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['ef7d20990532d25e0a22f96439676a8a', '36226eb832260cc4db7f15eb1ddd9607', '36226eb832260cc4db7f15eb1ddd9607']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(156672,1536) == "0f4c07f5fc878e2aa1805fefc0c25f7a"
}

