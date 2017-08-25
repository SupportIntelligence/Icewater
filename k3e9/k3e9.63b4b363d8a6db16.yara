import "hash"

rule k3e9_63b4b363d8a6db16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63b4b363d8a6db16"
     cluster="k3e9.63b4b363d8a6db16"
     cluster_size="439 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['bc1b46d5f50823fb5fb0fafcd7faf81c', 'c35cc78d5a9dd629c783acddde8d37e5', '565fe7561b8174b795a362aa5dcd353f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,256) == "fe88f5030104b15926c91a52764ce5e7"
}

