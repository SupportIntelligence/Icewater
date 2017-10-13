import "hash"

rule m3e9_411c3ac1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411c3ac1cc000b12"
     cluster="m3e9.411c3ac1cc000b12"
     cluster_size="1655 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple rahack backdoor"
     md5_hashes="['329132e9a06d5d4cd663c2747ac8f2b2', '3ecbd080d15651e1d7e771cab1776865', '2f8b4057e7ea1625a058161654c4ee5f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(61952,1024) == "6a039dc6f36c112b920bef9b8a73cb0e"
}

