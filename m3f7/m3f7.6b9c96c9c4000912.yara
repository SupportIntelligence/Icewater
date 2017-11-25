
rule m3f7_6b9c96c9c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.6b9c96c9c4000912"
     cluster="m3f7.6b9c96c9c4000912"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['07369b7d2da6830b4f89b8552872e7cb','209f359c623f1cd8ce6ceecc484f9173','d6077583c1c522937c5e5a94fba86477']"

   strings:
      $hex_string = { 456c656d656e7442794964282748544d4c3227292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
