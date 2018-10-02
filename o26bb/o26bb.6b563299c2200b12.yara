
rule o26bb_6b563299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.6b563299c2200b12"
     cluster="o26bb.6b563299c2200b12"
     cluster_size="509"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious banker attribute"
     md5_hashes="['73189ffb59551f34033831eaaccd11ead3784375','47bdbcdb9356b504c2ca6655d398d6edbcfafc7e','ba59f456dab6dbaf1ae8e1a5f98b0d7ed58c69f4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.6b563299c2200b12"

   strings:
      $hex_string = { faef8516fdff4dc11bdf92e7f8acd05ca3a036764a83bb03aeda5844a7b72571c05e13ce2d0b00478850fe483789b051e087b12c24ab35b4fb2e211518f7f9d3 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
