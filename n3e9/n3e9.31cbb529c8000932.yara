import "hash"

rule n3e9_31cbb529c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31cbb529c8000932"
     cluster="n3e9.31cbb529c8000932"
     cluster_size="6441 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['000c04ddab49f6098336d71f8bd5eb58', '0bd049ac95a50253e35f1fcb48406c64', '01881e9eb2dd05b0081dcbd3ba263d97']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(142763,1109) == "3e153f591f3d402724f89d1593be1ca7"
}

