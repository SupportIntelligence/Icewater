import "hash"

rule k3e9_139da164ddd39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da164ddd39932"
     cluster="k3e9.139da164ddd39932"
     cluster_size="519 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['af13a2cab7853a99b98dfd550e3f583d', 'bdde3bd1fec4e70ef53f800314532eeb', 'b1dba0f6334ac3519233b9ff7d7f587f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "10942184959ee54e3c7f95e54fa08bca"
}

