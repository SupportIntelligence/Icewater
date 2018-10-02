
rule m26bb_5362c10da6210916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.5362c10da6210916"
     cluster="m26bb.5362c10da6210916"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious attribute"
     md5_hashes="['c46dff09458a9d059c91f7b1e367c446894ad026','03c30f1129197d99ed1e23e8e086f47606f3a4a2','3b6cbdce0d78e88890f5674f4595a5faad432efc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.5362c10da6210916"

   strings:
      $hex_string = { bfb0ba2e3ede68d20be63bf09f23a6d177d9085e03710ddf10ce978b6a18c072f26b9d486656cc1c911e0611ac202a9913d384c5b14150b4b2f9a7305dca5cfa }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
