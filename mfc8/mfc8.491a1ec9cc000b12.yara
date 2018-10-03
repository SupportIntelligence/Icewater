
rule mfc8_491a1ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=mfc8.491a1ec9cc000b12"
     cluster="mfc8.491a1ec9cc000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker obfus androidos"
     md5_hashes="['bcc0ab5b99eca48b16de7db15768f245ae310feb','8238fa0261533485bc5394e5217ce58b0e12eb08','04fa5b26e8d9eeceb52e8f1d632cebf67cbde024']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=mfc8.491a1ec9cc000b12"

   strings:
      $hex_string = { 0300000064010000020000000000000001001c004400000003000000000000000001000028000000000000000000000007000000120000000404617474720008 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
