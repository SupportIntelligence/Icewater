
rule j26d4_5b199b55ca200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26d4.5b199b55ca200b32"
     cluster="j26d4.5b199b55ca200b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor razy uvpm"
     md5_hashes="['3fd02860c2c5e5022c4d360ad2a12cc88cf3ef3a','6b6854475332abe6e6ab67b4fafe4e054c8bce7d','f9ed73160de009f49d5e7ef6a685eb2ab8ff91aa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26d4.5b199b55ca200b32"

   strings:
      $hex_string = { d8e2584b811c9fd0eeafa0c7305490d91a9232687ef030bec041966d14ca991871016c27935e67f114b17da507ec708b4d7c081e8e26b7ebcbcd229a0a752cde }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
