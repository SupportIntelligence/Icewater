
rule n3e9_4b1284cbc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b1284cbc6220b12"
     cluster="n3e9.4b1284cbc6220b12"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur gena"
     md5_hashes="['7695149d2020a63d829e0b552e456c61','bb5594e1ff0629f96e56aea8477ec542','ee3e3345db574aed32443e5c706513c5']"

   strings:
      $hex_string = { 010001002020000002002000a8100000010050414444494e47585850414444494e4750414444494e47585850414444494e4750414444494e4758585041444449 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
