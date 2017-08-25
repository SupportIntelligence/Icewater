import "hash"

rule k3e9_6b64d34b8a4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b8a4b5912"
     cluster="k3e9.6b64d34b8a4b5912"
     cluster_size="541 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['30038b662102e00259e70f926529ac70', 'ab971a97dc4fbcaee118213e2cd2729a', '972ba4ad6bd56ed5a4e83214c68f580f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,256) == "de4797382bb8602c184c444f3aabdc95"
}

