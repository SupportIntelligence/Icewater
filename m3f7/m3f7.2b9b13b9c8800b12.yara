
rule m3f7_2b9b13b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.2b9b13b9c8800b12"
     cluster="m3f7.2b9b13b9c8800b12"
     cluster_size="242"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker html"
     md5_hashes="['01434ad195e4c14c5a5828b494f0a688','0185054195aa6430a965ec25a29927c8','0f63b39fafe762f50a02058be364f769']"

   strings:
      $hex_string = { 2e676574456c656d656e74427949642827506f70756c6172506f7374733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a3c2f736372 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
