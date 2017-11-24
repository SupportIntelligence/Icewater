
rule n3e9_0b9e95a1c2000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b9e95a1c2000b16"
     cluster="n3e9.0b9e95a1c2000b16"
     cluster_size="52"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="startpage razy downware"
     md5_hashes="['0221bf0540ab70e848267d926e600122','02c09d74f40f78aeb93bf6bd0beda501','5d068aa7b81f83000053628b5849bdea']"

   strings:
      $hex_string = { 65da7794998522594ae0ba278d41b62fa1c7b80334011c7e0984b3a88389354f1b699e66f2e253040f74a344cfbc5a55bb2530bd3ad64571410a50b70e547029 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
