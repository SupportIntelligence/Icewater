
rule n3e9_019a1499c2200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.019a1499c2200912"
     cluster="n3e9.019a1499c2200912"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce email"
     md5_hashes="['1256ca37409aef3877fd697724d1272d','139d4f60cd9c794bcb1ed0b6be264f0a','f586575094f438e1d5096f36e84e64f9']"

   strings:
      $hex_string = { 1d0700008be956ffd3fcab8bcde2f58b0424e8080000004d50522e444c4c00ffd08bf0e85c0700008be956ffd3fcab8bcde2f58b0424e80c00000057534f434b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
