import "hash"

rule k3e9_6b64d34b096b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b096b5912"
     cluster="k3e9.6b64d34b096b5912"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['a025619e5b6de0252b9280689a9fbe53', 'cdb348d4b92fa98b6523256035f34e9f', 'c9c750ed9c6453e489d67ea783ce00f0']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8252,1036) == "bf35bc45826b9aa0cee18bd0fde1c00c"
}

