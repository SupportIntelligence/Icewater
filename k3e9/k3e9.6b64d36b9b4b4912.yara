import "hash"

rule k3e9_6b64d36b9b4b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b9b4b4912"
     cluster="k3e9.6b64d36b9b4b4912"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['ba38aabcd38491d9d8c1fc3b5ea18ba9', 'b2bbbaebe2e6428a90763df487e9c626', 'a6001151f2cdb06c62b11181392af81e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(3072,1024) == "38207c64dbad69a73dd5f52b677dd369"
}

