import "hash"

rule m3e9_65cdf94e324d4bb2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.65cdf94e324d4bb2"
     cluster="m3e9.65cdf94e324d4bb2"
     cluster_size="236 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['bd36b654c25a404d7e228f3b8c25cd3e', 'bf5aabf685adfb000e8547b92364b1ec', 'bf5aabf685adfb000e8547b92364b1ec']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(78336,1280) == "d3a659f7bca6528afea38f524a5f56aa"
}

