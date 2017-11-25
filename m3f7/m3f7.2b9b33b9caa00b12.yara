
rule m3f7_2b9b33b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.2b9b33b9caa00b12"
     cluster="m3f7.2b9b33b9caa00b12"
     cluster_size="49"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['00c08d005b9ae561b2806777abe87509','091b1599822015eaf4252447dcb2da3b','5dba4b70b0bb4b683dea31d446be921c']"

   strings:
      $hex_string = { 742e676574456c656d656e74427949642827506f70756c6172506f7374733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a3c2f7363 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
