
rule m3e9_0b391066d9e30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b391066d9e30912"
     cluster="m3e9.0b391066d9e30912"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod zusy trojandropper"
     md5_hashes="['1d2088c1b5ea6d2594ab44dc5781a877','31dc29a990e07c355ff7a86303298b06','95952bb267744a7e2a2c7395c5c0adc5']"

   strings:
      $hex_string = { 3c4a3f72e8c0dbf160c38e9022ae3beebdbe9aad6523640d8728d3179f7509dd9856489d55415102696a2e1d4431f8fcd82711a5938d88cb1c7d6d2d0307ac18 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
