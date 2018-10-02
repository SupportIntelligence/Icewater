
rule n26bb_1be72e6ad8bb0b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1be72e6ad8bb0b16"
     cluster="n26bb.1be72e6ad8bb0b16"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="debc malicious androm"
     md5_hashes="['75cf0352ad9c35f9a427abcd77421e72f8ef6275','fe1112acdecdec0caa2a01b1c53c07144e04d502','a80a7999658ae4207bbbcbace758c03762c7d32d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1be72e6ad8bb0b16"

   strings:
      $hex_string = { eb0fe95c93feffbb03010380e8ba96feff8bc35f5e5b5dc2100090558bec83c4f85356578b5d148b750833c055688aa2410064ff3064892085db7c0583fb027e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
