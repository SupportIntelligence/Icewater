
rule n3e9_13ac5ed348001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13ac5ed348001116"
     cluster="n3e9.13ac5ed348001116"
     cluster_size="56"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa autorun blocker"
     md5_hashes="['040673a5db484df5e68c058ef455fabf','08c384d60cc8a6a6e3d5c3193bc96399','aabe20a8fad0558cf86caa608ec5121b']"

   strings:
      $hex_string = { c3bcfc61e138019bf376f7734f0cbf24501f855ed3aee2721e3355bd0f8d8b0e97020ab3a8c03b5c1232377c2f51de2e59cbb4aea11d4d3e96fecff1df1bd27d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
