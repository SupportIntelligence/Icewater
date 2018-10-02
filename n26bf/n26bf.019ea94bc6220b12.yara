
rule n26bf_019ea94bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.019ea94bc6220b12"
     cluster="n26bf.019ea94bc6220b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious coinminer attribute"
     md5_hashes="['72a2e0991bac7706bc0b471e8968be1f29ef85c9','72ca9cca119afbcde0b6b3d1d1fa08300bb0c5fb','b00c72ad646c787fd77d4d56629abd25023569da']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.019ea94bc6220b12"

   strings:
      $hex_string = { 3efe8ddccaac688ef90f78885d1aecc948be3f5e6d308979efed2da4330b20675785f44623c49ccf642612de1b4ad3cc476c05803c9517fba3f77ac072065f3d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
