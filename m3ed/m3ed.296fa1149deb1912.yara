import "hash"

rule m3ed_296fa1149deb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.296fa1149deb1912"
     cluster="m3ed.296fa1149deb1912"
     cluster_size="49 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['31297b222811ab7bbc6ae41473521f5a', 'de7ed9ab4aaa7c952c629d2dfe40a4fd', 'a2270a1eba62e85c1c2060fc0e945c52']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(89600,1536) == "4b9f88bd9590c052ba891343afbbb8c4"
}

