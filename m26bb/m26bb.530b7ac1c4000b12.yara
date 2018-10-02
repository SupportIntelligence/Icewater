
rule m26bb_530b7ac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.530b7ac1c4000b12"
     cluster="m26bb.530b7ac1c4000b12"
     cluster_size="40"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut malicious susp"
     md5_hashes="['411bfcda55fb801e423a6f7ba0db5c4bc34786f8','27405be21517f0fd6def6d0bc5f24a3cdf94cf02','616c0aaaa6acf2c9b008713d2c1331b26c32c007']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.530b7ac1c4000b12"

   strings:
      $hex_string = { 8e10e263d6da4b4288cbb3c9e45a591437d356eb629a24df7bf3f5d75fbe7ce1c21898fd6ffff49fce7ed8f7bc96b51c256b0038a6fcc11ffc415749f97d21c4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
