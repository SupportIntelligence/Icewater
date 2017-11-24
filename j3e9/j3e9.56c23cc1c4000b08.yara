
rule j3e9_56c23cc1c4000b08
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.56c23cc1c4000b08"
     cluster="j3e9.56c23cc1c4000b08"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="valla xorala valhalla"
     md5_hashes="['2bfd356ade3d04b53eec2a68e2d72aab','4955913158b09cdba4f767101a010b7d','c17aa7c2123c5666a6b84b94d8715768']"

   strings:
      $hex_string = { 33d2f7763c0bd2740140f7663c8987ef06000083bed000000000741b56578b7e5403fe8bcf2bcb8d77d8fdf3a4fc5f5e8386d000000028c703584f5200c74304 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
