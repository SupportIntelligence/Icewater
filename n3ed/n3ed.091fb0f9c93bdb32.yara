import "hash"

rule n3ed_091fb0f9c93bdb32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.091fb0f9c93bdb32"
     cluster="n3ed.091fb0f9c93bdb32"
     cluster_size="1015 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['369ef1651f38311adef5033f23ec37a0', '2a5f339a214fd7b97bf779d7b343599f', '6540aadd87b9a9c1f713582be3dd2e42']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(546051,1047) == "5238f707ac5ac25c6a9c24fe96b13a54"
}

