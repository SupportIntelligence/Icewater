import "hash"

rule n3ed_091fb0f9d9eb0b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.091fb0f9d9eb0b32"
     cluster="n3ed.091fb0f9d9eb0b32"
     cluster_size="209 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['8f97d9a918f4525e6b1b6c52f7e5a0a1', 'df0556f7b711c00600a6467dd5a60133', '0429004ffe8d17deaeee06bb05b6ddd7']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(546051,1047) == "5238f707ac5ac25c6a9c24fe96b13a54"
}

