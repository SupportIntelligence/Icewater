
rule n3e9_13a984bd0a801116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13a984bd0a801116"
     cluster="n3e9.13a984bd0a801116"
     cluster_size="67"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa autorun vilsel"
     md5_hashes="['07d2e7864e88aa63c1d3f99440f09b57','1e590177dca336db3757510d9b2aad6c','ae234107e04f8c6f988fe50792ae0eff']"

   strings:
      $hex_string = { c3bcfc61e138019bf376f7734f0cbf24501f855ed3aee2721e3355bd0f8d8b0e97020ab3a8c03b5c1232377c2f51de2e59cbb4aea11d4d3e96fecff1df1bd27d }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
