import "hash"

rule k3e9_539afac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.539afac1c4000b12"
     cluster="k3e9.539afac1c4000b12"
     cluster_size="25231 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="mydoom email malicious"
     md5_hashes="['008ea4620fb6bb484cd0b36315a84fc4', '031499e281d3bbd59ea07ddc69883227', '0005b09464f3dacd92c1323f67662677']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18944,1024) == "761dfca1f1eee46aa28db54312173457"
}

