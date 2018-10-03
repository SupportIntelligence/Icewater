
rule n2319_4b9a5ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.4b9a5ec1c4000b12"
     cluster="n2319.4b9a5ec1c4000b12"
     cluster_size="104"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="clicker faceliker script"
     md5_hashes="['72f5486f781fc28bf6ca6082e35f2ee3f1dddc77','216c2aaf7c771bbf60f4ed07c214306affd52dd5','ab110ed8686663ec3fdfc2f87c695b156ae65a0e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.4b9a5ec1c4000b12"

   strings:
      $hex_string = { 6e642d696d6167653a75726c28687474703a2f2f322e62702e626c6f6773706f742e636f6d2f2d51422d51726e5254534a492f55504d6945594b6f7a4a492f41 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
