
rule p26bb_4b110000909b0110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26bb.4b110000909b0110"
     cluster="p26bb.4b110000909b0110"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious tofsee filerepmalware"
     md5_hashes="['83862dbe4ffe09666f046bab25f7a4a6cbca917a','3f57ed507b4914a14cdc8a43ef73ba2612bd8135','08c07d1f8a4fa4e1f32fb76f79ff2a1d7baaf511']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26bb.4b110000909b0110"

   strings:
      $hex_string = { d34e98bc8fc3ad45eda0fffff146fc0fd6add0479b926fc291872622c97f226c891a120b1884cde5e203487aaae4b334020b64be2b54a1727bb438b7cba7d5de }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
