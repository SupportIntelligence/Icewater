
rule k2319_391a1ce9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391a1ce9c8800b12"
     cluster="k2319.391a1ce9c8800b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['9d3b46ac8779ac61b33b612f203362b9ce45b092','c951af2b82d05e238c8d7fc70f302516fd8760eb','489bcbd1f5994009004b0012508c41512f10182f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391a1ce9c8800b12"

   strings:
      $hex_string = { 29627265616b7d3b666f72287661722056356b20696e20753067356b297b69662856356b2e6c656e6774683d3d3d283134332e3645313c28392e323045312c33 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
