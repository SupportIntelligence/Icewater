
rule m2319_2c99197ad99bdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2c99197ad99bdb12"
     cluster="m2319.2c99197ad99bdb12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script fbook"
     md5_hashes="['3536ef21d4df46bb6e05b6c64a68a6eb','8065a0454fcdabc235513ddc72379d6c','b1fe10b749160c9cf60f74d2b313f459']"

   strings:
      $hex_string = { 6f63756d656e742e676574456c656d656e7442794964282748544d4c313327292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f57696467 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
