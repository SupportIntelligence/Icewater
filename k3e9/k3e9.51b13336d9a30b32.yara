import "hash"

rule k3e9_51b13336d9a30b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13336d9a30b32"
     cluster="k3e9.51b13336d9a30b32"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['ac1220ce64a1f644c297786065eaf236', 'de1abe4e2191584481f6bf9111ecfd9e', 'aca55db775bb2aa2306c8524e47b2348']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,256) == "a620adcc65253f2a65dfc0f69b10f2c4"
}

