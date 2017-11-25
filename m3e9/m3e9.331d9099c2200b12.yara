
rule m3e9_331d9099c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.331d9099c2200b12"
     cluster="m3e9.331d9099c2200b12"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['5326761ee26096c987d2a7aea9962330','78f207b1e9ee3885ad9ecd2fbf3f71e9','ccf0e50a65079d70fcbda30eb280c7c4']"

   strings:
      $hex_string = { fb090b36b3b2216439bc23d374fea1d85640f098776bab84db17f5e1d959cfe369bf2fe45533c11fda45f1155c0866ba945fa325ae0a4663c787505a8f08d54f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
