
rule m2321_29956a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.29956a48c0000b32"
     cluster="m2321.29956a48c0000b32"
     cluster_size="165"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0161d7b61b0b630cf3d13c4783b583f3','01da85095b4e8e120a19e85d86ab8f59','168588ec5a47d85bd34e34b8a3187c13']"

   strings:
      $hex_string = { a2448a94997370427558d77f69b827d0d6fb13a99e1a436597811237bbfd3698f8089c0c232f28726b25e75cdc2a9d53cb0f5ede8f478331c1e3e0ebc6ec10f0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
