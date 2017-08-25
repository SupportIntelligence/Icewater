import "hash"

rule k3e9_63b4b363d8929b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63b4b363d8929b16"
     cluster="k3e9.63b4b363d8929b16"
     cluster_size="348 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a0dd6f2081f466c51517eba7f70ef5ba', 'a7d55aa8b7383249fb9a7999be03a72a', 'ae3f41b36820411fce5ae39cb0ab1d7b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,256) == "fe88f5030104b15926c91a52764ce5e7"
}

