import "hash"

rule m3e9_691f97a1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.691f97a1c2000912"
     cluster="m3e9.691f97a1c2000912"
     cluster_size="6140 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['1267b4979cdf01561376346f4dc84413', '063ce7a2c5b71110ec884139666459fc', '154851d05c76ffd4776853f3d6b1446b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(15360,1024) == "b469f0a139e038b7a04b7aeb5167900b"
}

