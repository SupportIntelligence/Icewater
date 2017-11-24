
rule m2319_3b956a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b956a48c0000b12"
     cluster="m2319.3b956a48c0000b12"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['4cdc565dbc035fca3c8d543afc57b469','5113e892984c89c3255e25418aac0a2d','afa2032aeaa09f976da3711b23c1e978']"

   strings:
      $hex_string = { 616765273a20274c6f6164696e675c78323668656c6c69703b277d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e61676572 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
