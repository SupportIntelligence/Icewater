import "hash"

rule m3e9_439871e9c0800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.439871e9c0800b32"
     cluster="m3e9.439871e9c0800b32"
     cluster_size="1301 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['664ca56b3b794e0cf7d7c29c7873a758', '40a8071de32a99781d31c3105eb6489d', '2bff713a2645cfe22032367383308cbc']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57344,1024) == "ea3c338d29e9244b4487eec622d3ed34"
}

