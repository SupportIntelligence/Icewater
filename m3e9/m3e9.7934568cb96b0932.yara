
rule m3e9_7934568cb96b0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7934568cb96b0932"
     cluster="m3e9.7934568cb96b0932"
     cluster_size="84"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky wbna"
     md5_hashes="['07f59adcc517e650082df6767bdfe785','17a779b1671656f7630061dee4ecb41c','a68c7070127bd5903be55b8953736f29']"

   strings:
      $hex_string = { 054ab77a79746354898d120260caf6f3f6f3f1c7463f00000003858585b2bfbec0c1cacab93c262222090909090505053b707a7a79745d504c4b0c0764def6f3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
