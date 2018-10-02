
rule k2319_185294a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185294a9c8800b12"
     cluster="k2319.185294a9c8800b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e9b72eefcb828bc5bfd516d0a8e29661785e16ad','6a5cce6a59ad28b8f5ef9d4e0fec12d2da0e9461','29a3f2f02f1261b2c23caa83c994c298e69be21e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185294a9c8800b12"

   strings:
      $hex_string = { 2e33364532293e3d3133393f2830783234382c313139293a28307838392c3938292929627265616b7d3b76617220483169314b3d7b274f394b273a66756e6374 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
