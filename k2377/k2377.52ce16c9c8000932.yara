
rule k2377_52ce16c9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.52ce16c9c8000932"
     cluster="k2377.52ce16c9c8000932"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="html redirector script"
     md5_hashes="['12e817db0e366382482572f7cd3eb582','2473db1a45b26a100f0b9a997ad2cba4','c780001bc0e25ee003de0818397f95e9']"

   strings:
      $hex_string = { 69746c653d22203b2d2922206f6e636c69636b3d226a6176617363726970743a656d6f7469636f6e5f706f737428273b2d29272922202f3e3c2f74643e0a2020 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
