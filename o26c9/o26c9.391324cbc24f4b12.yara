
rule o26c9_391324cbc24f4b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c9.391324cbc24f4b12"
     cluster="o26c9.391324cbc24f4b12"
     cluster_size="230"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bsymem dnscleaner tsklnk"
     md5_hashes="['bd295221b6d38168e5856e5c00ab56feadff549f','b10c90c93fe5b5fdc469163e07e0a54dcaf6abb3','d297312eef83bad0f7e196bb5a8dcfb0a7a34c3c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c9.391324cbc24f4b12"

   strings:
      $hex_string = { c5488d4de0418bd5ff15defc1800443965707405458bcdeb358b4b2483f9ff750c41f7de451bc94183e103eb21b2c03aca76180fb7c166c1e8083ac2760dc1e9 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
