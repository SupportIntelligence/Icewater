
rule m3e9_2134a61e5ad3d3d2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2134a61e5ad3d3d2"
     cluster="m3e9.2134a61e5ad3d3d2"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik vbobfus"
     md5_hashes="['66bce863141cfb00dad27467ad1be359','a16243be7954a78a9a5d2b51852b3d4a','e515fa5e3f8a95a84b67c2872445ca67']"

   strings:
      $hex_string = { 01e9f17593234dba41a29aad31b89c62d5c295551419aa4ca4d296745106a8a38d605935817209e78e6d6f02b9f5eb6757d83a70a9ca5624f4d43458cca66965 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
