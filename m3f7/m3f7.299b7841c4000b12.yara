
rule m3f7_299b7841c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.299b7841c4000b12"
     cluster="m3f7.299b7841c4000b12"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script iscp"
     md5_hashes="['3f3b50873b2469e225b0e3349b59a447','4e3ebffae47502ce778947c863e0f2da','c333e30c6300e7eecb1bcb7a30fe4319']"

   strings:
      $hex_string = { 772f64656c69766572792f636b2e7068703f6e3d616431623662383026616d703b63623d494e534552545f52414e444f4d5f4e554d4245525f48455245272074 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
