
rule o231d_611495e9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o231d.611495e9ca000b12"
     cluster="o231d.611495e9ca000b12"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp clicker riskware"
     md5_hashes="['82fb5d0aa4ec8955c489f270f3fe9dd95be45edd','be78a4dda0fcda58f569e56800764062f4affe5a','7785bacd9a455a37e6ad33623b4d2274244571d9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o231d.611495e9ca000b12"

   strings:
      $hex_string = { c7bb55df05712632807ee87ffcf9e75fee8ffffad7cffbc39c6b1d099a11ec74381cf7876549e6402d776c068d4870be150342124130d054103c90985ad6ea4d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
