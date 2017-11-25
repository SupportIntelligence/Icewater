
rule m3f7_2b930526d91ad311
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.2b930526d91ad311"
     cluster="m3f7.2b930526d91ad311"
     cluster_size="9"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['216d44b0f8475ca0b42ff44637ba6ec8','45bc9521fdc2432bcaf75b7729e5e5e7','fd211596a16104e844e8442b2c23df3b']"

   strings:
      $hex_string = { 722e636f6d2f7265617272616e67653f626c6f6749443d3235303336303032313432363833353131373826776964676574547970653d426c6f67417263686976 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
