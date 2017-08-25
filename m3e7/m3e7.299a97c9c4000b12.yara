import "hash"

rule m3e7_299a97c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.299a97c9c4000b12"
     cluster="m3e7.299a97c9c4000b12"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="damaged file heuristic"
     md5_hashes="['4a05bda331af512b7ee637494a28ed0f', '0e997ba0f42bc917ef522c1734ec4dc2', 'c85cb1a6035372c22f8c69324f71146f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(30812,256) == "8006966076db0ea28ee81c9910c5d649"
}

