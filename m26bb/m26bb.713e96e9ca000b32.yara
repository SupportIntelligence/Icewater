
rule m26bb_713e96e9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.713e96e9ca000b32"
     cluster="m26bb.713e96e9ca000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virtob malicious susp"
     md5_hashes="['7d36af1abbfb9667bd0bf7b53456a24c6898ad77','9cad84bddfed83ef26e9a81d15498bc700b9cf6f','5bce290c037ffeca9df6f8e8005d00a73ce6ce2a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.713e96e9ca000b32"

   strings:
      $hex_string = { 72013ac66d692298043435142d61ab25bc9a0a67055e36ca08a58d50da26890a2952f070fd12c810ff1af488d144a7d7943fb2f2133187f8216860c4ac18c39b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
