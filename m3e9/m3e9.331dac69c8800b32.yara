
rule m3e9_331dac69c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.331dac69c8800b32"
     cluster="m3e9.331dac69c8800b32"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbinject jorik"
     md5_hashes="['1486666d88df6bb6627d7e77bea50773','ab160a0f79066ec336b313dddf637d53','bf02a6f299af8339db8a57b1f9be9d06']"

   strings:
      $hex_string = { 3b9e000b0da200111eb0002227bb002a6bac004552860048608a00556483004d679100566c940044749f00466ea0004a7aa5006578a1001b36c9002135c80031 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
