import "hash"

rule m3e9_16d1baa94a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d1baa94a9664f2"
     cluster="m3e9.16d1baa94a9664f2"
     cluster_size="1343 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="shipup razy zbot"
     md5_hashes="['6eb1b145efd7b61325664c01c97fa197', '916584d04ce84b8d718c5ccf11172c0c', '32c5d432458480f8e0809636f8a690fa']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(42496,256) == "f8b5f3c1d559cf50971b0fb68a18f093"
}

