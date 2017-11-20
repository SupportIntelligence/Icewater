
rule m3e9_21b1cd8e96e2e916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.21b1cd8e96e2e916"
     cluster="m3e9.21b1cd8e96e2e916"
     cluster_size="24"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ibryte optimuminstaller bundler"
     md5_hashes="['002de8ddc14997f80b423f53990d3310','0c5a2da2c88d83d9ec7990338c7abdbf','f7f456a13e74f27068cfed8f23218f44']"

   strings:
      $hex_string = { 5c5d5e5f6000004b4c4d15154e15154f505152535400003e3f40414243441545464748494a00003132333435363738393a3b3c3d00000025262728292a2b2c2d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
