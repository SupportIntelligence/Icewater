
rule o2319_1952ea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.1952ea48c0000b32"
     cluster="o2319.1952ea48c0000b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker clickjack likejack"
     md5_hashes="['215aef105261f65a048652c2134136b9764c9984','6ba0a8249e545171e27913f36f3f35c27249ec55','1910032f7c4611b8fe7c53c00639aed8680a5197']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.1952ea48c0000b32"

   strings:
      $hex_string = { 5d2a295c732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c286129297472797b696628657c7c216c2e6d617463682e50534555444f2e7465 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
