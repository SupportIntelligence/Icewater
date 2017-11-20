
rule m3e9_691f8566d9a31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.691f8566d9a31912"
     cluster="m3e9.691f8566d9a31912"
     cluster_size="219"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod malicious"
     md5_hashes="['023fc0ce1768d91e84b99c71ccab76b7','16e0a7a7dcc2202cba18c4e5e96fc10c','4b5a1ee1cb775d858722f0c780e2c2b5']"

   strings:
      $hex_string = { 725f847b9a46814ccc7cd0de43c9a171fae65733fdb49feb28dda5b66d127948aeb8c2c649e203f765bfd71bb105552e7a60fcaad1ba3f7707b77f7e382facea }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
