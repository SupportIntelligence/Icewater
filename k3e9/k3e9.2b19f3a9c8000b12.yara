import "hash"

rule k3e9_2b19f3a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b19f3a9c8000b12"
     cluster="k3e9.2b19f3a9c8000b12"
     cluster_size="23 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor injector"
     md5_hashes="['69bfc6c9231bde20a2d5de1aabfc7e7d', 'a3f05c0a847b46d5170e1249bc070048', 'b6ea80732f9551bfa3a3764dee277365']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

