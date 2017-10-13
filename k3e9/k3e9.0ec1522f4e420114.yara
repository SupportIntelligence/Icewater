import "hash"

rule k3e9_0ec1522f4e420114
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0ec1522f4e420114"
     cluster="k3e9.0ec1522f4e420114"
     cluster_size="211 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="crytex hublo virut"
     md5_hashes="['af492b120812daf5121c9d60370bd097', 'c3b945383ee5f190f5062f36f5b8f56b', '9077173196408df9c04fb5782cf05a8b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,1024) == "0a69d25c350be8b881a7571f86c65674"
}

