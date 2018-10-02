
rule k2319_391a1de9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391a1de9c8800b12"
     cluster="k2319.391a1de9c8800b12"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['aa0414022e90fcfb8c032540d4c30f7e90c88ddb','665a4de633a41484d7446be73b14705dd0378e92','8fef1259e002f8670afed90825c8a1e354aa9fb7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391a1de9c8800b12"

   strings:
      $hex_string = { 29627265616b7d3b666f72287661722056356b20696e20753067356b297b69662856356b2e6c656e6774683d3d3d283134332e3645313c28392e323045312c33 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
