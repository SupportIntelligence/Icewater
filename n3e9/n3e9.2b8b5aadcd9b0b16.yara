
rule n3e9_2b8b5aadcd9b0b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b8b5aadcd9b0b16"
     cluster="n3e9.2b8b5aadcd9b0b16"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="heuristic corrupt corruptfile"
     md5_hashes="['2e2cc1e487785aa5ae9c6c01965ca27a','322c8a5c9a656b63b1faa6b0a5f4d7de','fd35a503a1f85c47541250b478eca674']"

   strings:
      $hex_string = { 8945fceb24b878384f00b1418d6424003acd74098a4801404284c975f3382875638b45fcc1e30603da464783fe0472c38b750883f80173120fb6c350e8ef9fff }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
