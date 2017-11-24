
rule o3e9_2865448a04424a9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2865448a04424a9a"
     cluster="o3e9.2865448a04424a9a"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['0f9f7f98f087994a78431d39826fb899','151c0a6716ed8b976d8d92a546c53bc2','ab61250d47f7bb58946bbf81e121d6ce']"

   strings:
      $hex_string = { 0c5aa0cbfa032175a777f8c5f46766f748865cc93de60893cdf64cde0e33a33238319b5390a9dceda1a52e026afb1bd6912f18d9ecccc1548207f3b68efdac10 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
