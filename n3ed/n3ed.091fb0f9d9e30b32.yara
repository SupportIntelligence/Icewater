import "hash"

rule n3ed_091fb0f9d9e30b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.091fb0f9d9e30b32"
     cluster="n3ed.091fb0f9d9e30b32"
     cluster_size="484 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['7c08134e9edf9d8fba5a3cd82b102c16', '6372d4a1fc148c0099aa5e38016a8bb9', 'a60085e4c07540c152b76c59bc40ea44']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(546051,1047) == "5238f707ac5ac25c6a9c24fe96b13a54"
}

