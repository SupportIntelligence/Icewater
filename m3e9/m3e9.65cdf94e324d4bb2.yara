import "hash"

rule m3e9_65cdf94e324d4bb2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.65cdf94e324d4bb2"
     cluster="m3e9.65cdf94e324d4bb2"
     cluster_size="231 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['18fd69617b021280e48b4fc8a62ba8b0', 'b7a0c7efbdef50efb3d6d7dc6723a3dc', '098cd6c405231621393a31716b4d700f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(80384,256) == "97d3acaa4732eff4c8bdf0d777a5d813"
}

