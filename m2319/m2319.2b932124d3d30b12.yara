
rule m2319_2b932124d3d30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b932124d3d30b12"
     cluster="m2319.2b932124d3d30b12"
     cluster_size="26"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['16c28020496171da76ff36b2875e5703','1aaf1104987e75068f9ff2cde6d3ff82','ba1163f93263b8bfd0ba2f426bf91ce4']"

   strings:
      $hex_string = { 6d344264772d762d4359772f554773695f647256796e492f4141414141414141577a452f46575f6850786b746252672f7337322d632f3130342e6a7067272077 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
