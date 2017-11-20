
rule m3e9_692c244dc9a31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.692c244dc9a31912"
     cluster="m3e9.692c244dc9a31912"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbobfus"
     md5_hashes="['3d943fa70159f1c5176902a2cb1b6908','6ccf611c017707ec1490cce7b2d68228','ed170d4c56f02e807e32ccfefacadee3']"

   strings:
      $hex_string = { 2a2370ff94080068062a46b0fe28d0fe0f2728f0fe010004c0fe0a44000c0004c0fefbefa0fe3a90fe3f00fbef80fe603178ff32040074ff70ff36120040ff20 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
