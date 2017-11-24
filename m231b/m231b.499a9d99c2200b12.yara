
rule m231b_499a9d99c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.499a9d99c2200b12"
     cluster="m231b.499a9d99c2200b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker html clickjack"
     md5_hashes="['02baeef4a5c461a2d62117136ed5991d','830df5d2f681f91c968ed5e23a7fb5fa','fc9245c95f38eee2d9611da729ac63be']"

   strings:
      $hex_string = { 784d6f64756c6555726c273a202768747470733a2f2f7777772e626c6f676765722e636f6d2f7374617469632f76312f6a7362696e2f3333373337303837332d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
