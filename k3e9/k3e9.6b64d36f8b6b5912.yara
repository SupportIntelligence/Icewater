import "hash"

rule k3e9_6b64d36f8b6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36f8b6b5912"
     cluster="k3e9.6b64d36f8b6b5912"
     cluster_size="26 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['bd6a144434f131fb3db43dd0b82c4d81', '08fdb1416b036f844c77732fe68c2c6a', 'aadc2e63eea237a5fafadfa5885d010b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(23792,1036) == "663025776e46806a4b7c0489da905646"
}

