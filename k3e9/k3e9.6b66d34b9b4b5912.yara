import "hash"

rule k3e9_6b66d34b9b4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b66d34b9b4b5912"
     cluster="k3e9.6b66d34b9b4b5912"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['de4ccc349faa14beb062267cc05bf007', 'f781bfe6a49c7f3db16e6c7df2866a14', 'c9cd5e12f537dbd0ce4a19e79714e764']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8252,1036) == "bf35bc45826b9aa0cee18bd0fde1c00c"
}

