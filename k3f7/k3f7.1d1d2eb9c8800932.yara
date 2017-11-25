
rule k3f7_1d1d2eb9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.1d1d2eb9c8800932"
     cluster="k3f7.1d1d2eb9c8800932"
     cluster_size="42"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['00e0c165e7e45119fedbb47d140cf2c5','1a10d9fd6fa1710ca4ebd5a22fc3c1e4','7d733e2465e9308280348e0ab213d22e']"

   strings:
      $hex_string = { 696e672e66726f6d43686172436f6465287061727365496e742874292b32352d6c2b61293b0d0a0d0a743d27273b7d7d785b6c2d615d3d7a3b7d646f63756d65 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
