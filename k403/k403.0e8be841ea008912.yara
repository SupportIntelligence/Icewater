
rule k403_0e8be841ea008912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k403.0e8be841ea008912"
     cluster="k403.0e8be841ea008912"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="onlinegames gamethief winnt"
     md5_hashes="['2480239def4b989ff0a3a5e47812e494','4c5290682cf490135e3b5467053f2c6b','d47d347cbe5b4c2872343de7dd108be0']"

   strings:
      $hex_string = { b881792c3a7b141b9bd6048f7d32160676350c6e98197c9d3c9e8f1c476322278a332a1c6462c606721cde8c50c09c949c9c16985e1de42b200bc49b9365dcb6 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
