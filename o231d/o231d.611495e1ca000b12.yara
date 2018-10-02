
rule o231d_611495e1ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o231d.611495e1ca000b12"
     cluster="o231d.611495e1ca000b12"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp androidos scamapp"
     md5_hashes="['ef103f76a612d1fba7040dc9c40268db2216755c','cf94d514bb43a878ac68467f5bfff13db79ff92f','4125db669f0c2ba57eb685c886d3c46bcc7fadcc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o231d.611495e1ca000b12"

   strings:
      $hex_string = { c7bb55df05712632807ee87ffcf9e75fee8ffffad7cffbc39c6b1d099a11ec74381cf7876549e6402d776c068d4870be150342124130d054103c90985ad6ea4d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
