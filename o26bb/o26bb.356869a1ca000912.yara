
rule o26bb_356869a1ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.356869a1ca000912"
     cluster="o26bb.356869a1ca000912"
     cluster_size="311"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="downloadsponsor malicious unwantedsig"
     md5_hashes="['dbe4f6bf898a652764070310928048108fc894b5','60484d6ac6ac50a55bd64accbde3fb9bf267cfc3','847092ee7ee8f092a165897b3fffd712833bfbb8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.356869a1ca000912"

   strings:
      $hex_string = { 1b104996515a5d4e32164d7f22dc856b82ec1a751572b0d45e94e68055b23c5bc186d1c626c2cf27adea34180cb6442b1c84f0d7bca3178b25130881c99ccc69 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
