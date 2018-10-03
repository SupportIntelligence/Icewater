
rule m26bb_53666e1b1ee31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.53666e1b1ee31912"
     cluster="m26bb.53666e1b1ee31912"
     cluster_size="1777"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore alphaeon malicious"
     md5_hashes="['1091df4f6c6824315db84abe36efbe396e941051','d20c6d13d924a653580b51be9997d9186043c8ff','30b12a16795567f69b6c759d41ece63434197712']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.53666e1b1ee31912"

   strings:
      $hex_string = { 96e166729a28c8f91e407f8ba2ae61ec3c036b30112d579b5638779fa554539ecbfc3121a9b8249368d6af4d417dfe91a83e366281071f6e74d483e4b0ff3b0c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
