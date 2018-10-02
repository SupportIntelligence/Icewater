
rule n26bb_32bb29e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.32bb29e9c8800b12"
     cluster="n26bb.32bb29e9c8800b12"
     cluster_size="208"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="floxif pioneer malicious"
     md5_hashes="['c9b5d1b9bb7e071f652fc5ca5a4690166ecbda47','0dd63ba2565a822548f566620af2fc44b7615a3a','a14b39bbadca73bd7ac5c55c6e198c19a92a3060']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.32bb29e9c8800b12"

   strings:
      $hex_string = { eb83e0010bc803c94e85f67ff08b5dd8d1e966890c97423bd37eca8b4dfc5f5e33cd5be88a2500008be55dc3558bec83ec148b4508834df8ff530fb75a025657 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
