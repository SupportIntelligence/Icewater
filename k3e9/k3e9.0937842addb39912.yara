
rule k3e9_0937842addb39912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0937842addb39912"
     cluster="k3e9.0937842addb39912"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installm unwanted downware"
     md5_hashes="['0a4e221885e635a9a105fba65aca4311','2409dcc5b27eaead2e4ab0420d81b3fe','cba355e1cf3e0185b7a7b2c0fc6f7247']"

   strings:
      $hex_string = { bf8f4046cb3d2060caf76b4f0fd1288d05a803bd86422b6ae7c6f4a1fa0c9d7122022d82eb0153a879ecadb14c3067f8de7b5b75ea80485954b02699f9431d4d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
