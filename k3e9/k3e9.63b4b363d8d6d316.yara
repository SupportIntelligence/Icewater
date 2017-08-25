import "hash"

rule k3e9_63b4b363d8d6d316
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63b4b363d8d6d316"
     cluster="k3e9.63b4b363d8d6d316"
     cluster_size="86 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e57bb9c006264fa405855d63669bbc4e', '785a11a0345acd6208cef362ed95253c', '3e1d5ec336fccb6be17bf1ad36d8d4ae']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,256) == "fe88f5030104b15926c91a52764ce5e7"
}

