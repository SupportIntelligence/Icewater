import "hash"

rule m3e9_439c71e9c0800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.439c71e9c0800b32"
     cluster="m3e9.439c71e9c0800b32"
     cluster_size="9952 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut patched virux"
     md5_hashes="['0670a7238cbb812f828dc84c4d702bd3', '04afcf1edacdf16236d3366685a64426', '093f06712ee7f592244e3e26df3a545a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57344,1024) == "ea3c338d29e9244b4487eec622d3ed34"
}

