import "hash"

rule n3e9_191312dadee30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.191312dadee30912"
     cluster="n3e9.191312dadee30912"
     cluster_size="5578 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="vbkrypt manbat injector"
     md5_hashes="['27e50dab68e292f14f432c3507ccc2e2', '013755236923724769832fd89b254ded', '1c6a230ca4ba6e41b9ece98c0fa1da27']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(398336,1024) == "ac4c406ac6ab743068339498fb9607ab"
}

