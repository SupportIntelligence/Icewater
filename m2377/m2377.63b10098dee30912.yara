
rule m2377_63b10098dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.63b10098dee30912"
     cluster="m2377.63b10098dee30912"
     cluster_size="40"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit script html"
     md5_hashes="['00e8306f8c317f3262b3e7d07daf323d','089724bb7e3f9997c8a73f043041d405','63aefa626e391343aadcfeb53eb27aea']"

   strings:
      $hex_string = { 434c6e6728222648222026204d6964285772697465446174612c692c322929290d0d0a4e6578740d0d0a46696c654f626a2e436c6f73650d0d0a456e64204966 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
