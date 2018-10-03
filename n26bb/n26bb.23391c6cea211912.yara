
rule n26bb_23391c6cea211912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.23391c6cea211912"
     cluster="n26bb.23391c6cea211912"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor blamon malicious"
     md5_hashes="['de67bc7632c94892d62ff7f66148eb2ab84eec2e','c379ddb0b06371d48076b7b3d69f0d574d492bdd','74799570e6eeb147071b813710c4817182fa2989']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.23391c6cea211912"

   strings:
      $hex_string = { c88d441aff83e1033bc2f3a47226b3a18a0880f92074093acb75153858ff751084c97d0583e802eb01483bc273e2eb04c64001008bfa83c9ff33c0f2aef7d149 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
