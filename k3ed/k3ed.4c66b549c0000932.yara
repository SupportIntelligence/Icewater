import "hash"

rule k3ed_4c66b549c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.4c66b549c0000932"
     cluster="k3ed.4c66b549c0000932"
     cluster_size="23 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy ebgx malicious"
     md5_hashes="['8789611b07199c537305fda5e3ddd589', 'c5e25ff1e66ea7f1600044547b6f3612', '598f5d4dde65d34346c8e87988158e3e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18944,256) == "fac632e2bcce3fb1200e7c6f3378f0af"
}

