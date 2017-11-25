
rule m3f7_11aa5749ea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.11aa5749ea210912"
     cluster="m3f7.11aa5749ea210912"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script autolike"
     md5_hashes="['03eb387487f03e44c8e6b05923bc1719','5abbca8034011a6c696c252f82cc0ae5','e6fbf8b5e553c03ac6da7afd5158bea9']"

   strings:
      $hex_string = { 6e742e676574456c656d656e74427949642827506f70756c6172506f7374733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
