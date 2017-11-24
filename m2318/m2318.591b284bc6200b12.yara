
rule m2318_591b284bc6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.591b284bc6200b12"
     cluster="m2318.591b284bc6200b12"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['013d3386e44873fc51cf2a279f1832b1','06c258cf78bbb848a5230bd0e491c160','efc3119fd1b5c8a9e26167a354e30825']"

   strings:
      $hex_string = { 33434346433536443739453337314144354132453930303435463938363833414435383031424234433343373130344337414632323936414630343632444237 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
