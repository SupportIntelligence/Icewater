import "hash"

rule m3e9_73165a8d9eb70b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.73165a8d9eb70b32"
     cluster="m3e9.73165a8d9eb70b32"
     cluster_size="268 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="swisyn bner mofksys"
     md5_hashes="['cca5496c8fcf7ffc4da9d4a49932c381', 'b0a2188e042f640e4b42c6d4f0d637e9', '8eb6b639c07769f68c277c181c0df511']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(131328,256) == "4db421c571a8715880e6961228c04480"
}

