
rule m2319_3b9f6a49c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b9f6a49c0000912"
     cluster="m2319.3b9f6a49c0000912"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['0e35ed974ee3129bc2df66a3fe7eb812','1525ad761f2c5ac7c6201ac65ea438b0','9b56cf99373a5117d4af54992e6115da']"

   strings:
      $hex_string = { 54344e6750795f716548492f4141414141414141425f6f2f634f553159356650366d512f7337322d632f526f6e616c646f2e6a7067272077696474683d273732 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
