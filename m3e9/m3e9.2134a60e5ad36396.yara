
rule m3e9_2134a60e5ad36396
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2134a60e5ad36396"
     cluster="m3e9.2134a60e5ad36396"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik malicious"
     md5_hashes="['728c7a09f67ddf14f3006a846d0d073a','a2ccc59abd6267c26368bfbe066ff8ab','eeb66ca0a44d5836146a8c38a7adb2d5']"

   strings:
      $hex_string = { 01e9f17593234dba41a29aad31b89c62d5c295551419aa4ca4d296745106a8a38d605935817209e78e6d6f02b9f5eb6757d83a70a9ca5624f4d43458cca66965 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
