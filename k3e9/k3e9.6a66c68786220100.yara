import "hash"

rule k3e9_6a66c68786220100
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a66c68786220100"
     cluster="k3e9.6a66c68786220100"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['9d17ac74e908541c0012073db7a7f5cb', '9d17ac74e908541c0012073db7a7f5cb', '9d17ac74e908541c0012073db7a7f5cb']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4352,256) == "9a1dd280d47f8a52d50d6f78ec240b52"
}

