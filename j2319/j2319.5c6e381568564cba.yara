
rule j2319_5c6e381568564cba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.5c6e381568564cba"
     cluster="j2319.5c6e381568564cba"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="webshell html script"
     md5_hashes="['2887d863397e67df16d8808c14462c8e38f10bea','04b64efe9afc5c071473756019dce7bdc93971d6','0e72e8c1ce240dbaee149f308208f6a6a39e467b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.5c6e381568564cba"

   strings:
      $hex_string = { 742e636f6d2e706b202d2057534f20322e363c2f7469746c653e0d0a3c7374796c653e0d0a626f64797b6261636b67726f756e642d636f6c6f723a233434343b }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
