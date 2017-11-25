
rule m3f1_4917a848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f1.4917a848c0000b12"
     cluster="m3f1.4917a848c0000b12"
     cluster_size="642"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakeinst androidos smsbot"
     md5_hashes="['004c22b105d20436a44c7718525372db','005ba29949cf4b21aec00891d88d5d82','085fe3a19bf4b20540ed0bb500127e35']"

   strings:
      $hex_string = { 044b043f043e043b043d044f0442044c0441044f0420003204200044043e043d0435042e000000000000022001c80500007f00000074006500730074002e0061 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
