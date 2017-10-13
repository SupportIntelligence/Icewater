import "hash"

rule n3e9_396c1099c2220932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.396c1099c2220932"
     cluster="n3e9.396c1099c2220932"
     cluster_size="58 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="lethic strictor trojandropper"
     md5_hashes="['d4156c16c3260677b522bb596fb5ec81', 'c167ca8e28c55addc4d3d9e93f498eb4', 'cb9633b4352ef21e53eb146818dcd30a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(173056,1024) == "ce2f94dc96e8f8bf8f5033bdc78bde37"
}

