
rule o3e9_19b358eb14714cf3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.19b358eb14714cf3"
     cluster="o3e9.19b358eb14714cf3"
     cluster_size="257"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['005f0be7888507cc4c8fb01cd4145731','00f73cb734c30723381dc2aa0ebe5d4c','0bd183e7f021c8fabea5781112670c18']"

   strings:
      $hex_string = { c0c944df0abc601bd95372136cb56010e816dec5c85374560b62966a5eeffe31f003b94b5dc013ee24c278621a76d478b5c7d821f142a45528409ca36e093a09 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
