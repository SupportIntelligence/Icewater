
rule m2319_2b932924d3d30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b932924d3d30b12"
     cluster="m2319.2b932924d3d30b12"
     cluster_size="32"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['0c352500195cf83b913e6c33a1388dbe','153a409eae7c2368a59a8bf94ebd94ab','7eedad0d5184a307f634eba8b6b45a7a']"

   strings:
      $hex_string = { 6d344264772d762d4359772f554773695f647256796e492f4141414141414141577a452f46575f6850786b746252672f7337322d632f3130342e6a7067272077 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
