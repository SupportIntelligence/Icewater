
rule m3e9_3b955cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3b955cc9cc000b12"
     cluster="m3e9.3b955cc9cc000b12"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma emotet"
     md5_hashes="['004c73dac6b327211967bf823ba47604','0a0d98c669d9c69bfc8f5e622cc96a13','fe01793f70437fb1a206dea855e009b4']"

   strings:
      $hex_string = { 4ef9c47372c95c8fc62ffabfa7236afad36d1f9c3618fe60caed5fad960f9414f1b859c1a33abd3f5d08ee457cac8c974c6375c853c0d78b797daa304a7477bb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
