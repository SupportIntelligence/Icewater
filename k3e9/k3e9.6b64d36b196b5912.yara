import "hash"

rule k3e9_6b64d36b196b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36b196b5912"
     cluster="k3e9.6b64d36b196b5912"
     cluster_size="36 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['a2e2c667400e1b8e8c8e5170ac5b8b17', 'c064c7b9fa41f9a2f3522b8173df6df4', 'a2e2c667400e1b8e8c8e5170ac5b8b17']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24828,1036) == "b430fb8cdfb0eaa02d3e9c2620da748a"
}

