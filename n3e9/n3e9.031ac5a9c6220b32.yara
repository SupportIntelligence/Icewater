
rule n3e9_031ac5a9c6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.031ac5a9c6220b32"
     cluster="n3e9.031ac5a9c6220b32"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce email"
     md5_hashes="['235012c5535ece3afefac5e9f3dc93b2','62af657307c0bf5607616a50e26651e4','deafcec6dd27e900350b7f62bd8c9bd6']"

   strings:
      $hex_string = { d8000000ff96c00000008b65fc618b45f8c9c20800c804000060b8000100002be08bd4505452ff968000000058e81d02000048454c4f206274616d61696c2e6e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
