
rule m3f7_19999cc1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.19999cc1c4000b32"
     cluster="m3f7.19999cc1c4000b32"
     cluster_size="156"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['01f380e79757bd70ccb4293207d051da','0336be2398d2e3fd92debc81234af070','179889799f0ba894d93f5a20ff7858a1']"

   strings:
      $hex_string = { 6f63756d656e742e676574456c656d656e7442794964282750726f66696c653127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
