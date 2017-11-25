
rule k3f7_3ad595a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.3ad595a1c2000b12"
     cluster="k3f7.3ad595a1c2000b12"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['048a373ea2ab134a56f23d4647c7aad6','0bf4a3babb3841e5357c185fa13e3587','a3cf089dc71d321eaa489535be358b3d']"

   strings:
      $hex_string = { 696e672e66726f6d43686172436f6465287061727365496e742874292b32352d6c2b61293b0d0a0d0a743d27273b7d7d785b6c2d615d3d7a3b7d646f63756d65 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
