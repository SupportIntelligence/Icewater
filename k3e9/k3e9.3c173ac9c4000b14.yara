import "hash"

rule k3e9_3c173ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c173ac9c4000b14"
     cluster="k3e9.3c173ac9c4000b14"
     cluster_size="89 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['a6c50c3ac94abcc581a7c026240002c3', 'c08321a9a6a66f3d454ec6ded1bbe9eb', '6b8f9de0d4b12f0b216cce83e7faf3a3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

