
rule m3f7_199cf1a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.199cf1a1c2000b32"
     cluster="m3f7.199cf1a1c2000b32"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['00d68064070e7e4258d2e046911b8d30','73f4a2651f43d6003e1921677835eb43','f5e261298daeb2e67efdb7ecddd3dae1']"

   strings:
      $hex_string = { 456c656d656e7442794964282748544d4c3327292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
