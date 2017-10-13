import "hash"

rule n3e9_1318e5a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1318e5a1c2000b32"
     cluster="n3e9.1318e5a1c2000b32"
     cluster_size="509 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple virut rahack"
     md5_hashes="['b8b06f564ef42424975525b49ddc9426', '05bcfc85bf7d348ce32e4a43ff0af867', 'ad48ba3dda99d2ba6ac818f55ccea3d2']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(61952,1024) == "6a039dc6f36c112b920bef9b8a73cb0e"
}

