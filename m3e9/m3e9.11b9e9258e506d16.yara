
rule m3e9_11b9e9258e506d16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.11b9e9258e506d16"
     cluster="m3e9.11b9e9258e506d16"
     cluster_size="289"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cerber ransom shipup"
     md5_hashes="['0026ea1f86b2dcaff234ed45857dd108','0053b9f8ea237a97d36148150238423a','159fc9e2c774734d6de351971efed4b6']"

   strings:
      $hex_string = { 314d4d3631655d360900000000000000005d253611552d36f94c3536f1640137e55e0100e95b0100e95b0100e95b0100e95b0100e95b0100e95b0100e95b0100 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
