
rule m2319_2b9b9199c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b9b9199c2200b12"
     cluster="m2319.2b9b9199c2200b12"
     cluster_size="9"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['0d7308cca6f960fcbdd0ac9bbe654f94','1e4cc842f13390c3a19ff339a26fc626','f90f4ff2af32829f3b07640cd8bc9b60']"

   strings:
      $hex_string = { 783b206261636b67726f756e643a75726c28687474703a2f2f342e62702e626c6f6773706f742e636f6d2f2d62394f456d56644c3651342f5552415f424c374f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
