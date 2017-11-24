
rule o3e9_6936949d9ec31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.6936949d9ec31932"
     cluster="o3e9.6936949d9ec31932"
     cluster_size="61"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor flooder malicious"
     md5_hashes="['0af3d238940e04eab601b5127a6ec847','1124fc0a74efaf1c8a9576326b4ff1f7','6d42b5de20b6a450367fbce5dee892d0']"

   strings:
      $hex_string = { a3e0c2e3391c5c10db671ddab9e9dcb2274cf09ae76181cfc44d06336efbcd4800f65d3d90247a80fdbf9504ab34a22e32ef18ca5f76b8889bbdecf54fc842b3 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
