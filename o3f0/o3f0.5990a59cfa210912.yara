
rule o3f0_5990a59cfa210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f0.5990a59cfa210912"
     cluster="o3f0.5990a59cfa210912"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="filetour symmi fnuj"
     md5_hashes="['09aa0fbd0f1e155f1465ed9807b1ba2c','1afb72145e8c459acdfe1ac6042ed1cb','fbab3afe3250c1f11f8d5a1ff5bd442b']"

   strings:
      $hex_string = { 6b07325184b0f662beb738defb6e36398ae4f2ddc4616fcdcb52a5297981bd976877c3f3019cfcf09c54f93073fd4f8c8da7c23ca29699645910e1b51f50ab60 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
