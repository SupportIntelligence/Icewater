import "hash"

rule k3e9_3b24949786220100
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b24949786220100"
     cluster="k3e9.3b24949786220100"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b9cdb23d47807dba73c1637759eda087', '661e1650f7765db1199756660ba2393d', '7f096bb23c737fd2f66026b586d98096']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,256) == "b98c324b2bff1dc76c923acdf9437671"
}

