
rule m3e9_1b9326394a9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1b9326394a9b0b12"
     cluster="m3e9.1b9326394a9b0b12"
     cluster_size="19"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['1c8e57daf4438b18925695e64c08f4fd','5157863aa4e2481589fa39879eb8b0e9','dd0e1e7059ed32a4ee1ff61250200f1e']"

   strings:
      $hex_string = { 725f847b9a46814ccc7cd0de43c9a171fae65733fdb49feb28dda5b66d127948aeb8c2c649e203f765bfd71bb105552e7a60fcaad1ba3f7707b77f7e382facea }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
