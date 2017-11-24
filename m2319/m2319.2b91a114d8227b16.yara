
rule m2319_2b91a114d8227b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b91a114d8227b16"
     cluster="m2319.2b91a114d8227b16"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['a46077cbfd9b132e66db4c92a6f528a8','ae7c429a5b84f37dd2b2d5c58caee579','d333bb1c998db95e69979b5b956216c7']"

   strings:
      $hex_string = { 2e676574456c656d656e74427949642827506f70756c6172506f7374733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a3c2f736372 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
