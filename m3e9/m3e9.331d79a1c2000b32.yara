
rule m3e9_331d79a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.331d79a1c2000b32"
     cluster="m3e9.331d79a1c2000b32"
     cluster_size="29"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi superthreat"
     md5_hashes="['1bd46ec4392780d2b5fa0408a24164c8','210d6fe6ba31f67933114852fa63184b','bc1df9296ff0fbde7cabd336b4d9ee74']"

   strings:
      $hex_string = { 3b9e000b0da200111eb0002227bb002a6bac004552860048608a00556483004d679100566c940044749f00466ea0004a7aa5006578a1001b36c9002135c80031 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
