
rule o3e9_091512ccea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.091512ccea210912"
     cluster="o3e9.091512ccea210912"
     cluster_size="11"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="unwanted crawler webtoolbar"
     md5_hashes="['0f9c72b5903868182bffd2c1c64e8c53','2e9ad203adb4841a95fbb273eec19e25','f885df1dc7304d22bcf6a803ca95c263']"

   strings:
      $hex_string = { cc693c1e25b958b2e7f351c37749154830b3aacf3f3bb70f4fc6ae99db3820a69dea8c52e1fa86ef92bc0d84fd6b5da3eddd9a4e34102cd5fe4dc0075ee95564 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
