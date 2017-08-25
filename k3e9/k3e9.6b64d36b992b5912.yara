import "hash"

rule k3e9_6b64d36b992b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b992b5912"
     cluster="k3e9.6b64d36b992b5912"
     cluster_size="24 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['b595426f73e5cec8511702dc385e06f2', 'dcc76e9c162c2598a374f098df866dd4', 'cec2e2fbd7d4ac915b613af1798b12da']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(11360,1036) == "344675ffeadac8a29fb9e31d1c7725a6"
}

