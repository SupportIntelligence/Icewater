
rule m2319_3b9142ceea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b9142ceea210912"
     cluster="m2319.3b9142ceea210912"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['572256a416f2aa1c31b6c153b537eb17','7766e9819be4e06a48e1a5d48fe24afe','f36c1c705fc9f01f688e3bba0983108b']"

   strings:
      $hex_string = { 656d656e74427949642827466f6c6c6f776572733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a3c2f7363726970743e0a3c2f626f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
