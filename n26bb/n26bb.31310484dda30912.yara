
rule n26bb_31310484dda30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.31310484dda30912"
     cluster="n26bb.31310484dda30912"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious nymaim"
     md5_hashes="['b68cff79d448a5ed998a47dd3c9263de315744a8','a48e6452d597cc73d9ab8c65df360c85bdd50a72','7af753bd5aade7b1e4c8bb6dd420ec5a5e98bfe9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.31310484dda30912"

   strings:
      $hex_string = { 7a10c09cdb2202f0764012d4b4b56bc83634b899fb4e003a196805afca553d2a6afe0801cb5a487c2fe00ae9b911657e1a4b3f8cbf1b69396f2928579f9d66f2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
