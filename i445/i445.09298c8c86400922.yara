
rule i445_09298c8c86400922
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.09298c8c86400922"
     cluster="i445.09298c8c86400922"
     cluster_size="4"
     filetype = "MS Windows shortcut"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="darkbot dorkbot winlnk"
     md5_hashes="['3742063c352397196440ef5bfcbb05a4','b7ef394c2ff90b79694abc08fcaa6d8a','f05036bf113d84cce9073ca5cec1931b']"

   strings:
      $hex_string = { 2b89cb016148dd8b2b89cb01009e04000300000007000000000000000000000000000000290114001f50e04fd020ea3a6910a2d808002b30309d19002f433a5c }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
