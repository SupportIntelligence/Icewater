
rule m2321_5a8944423543485a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.5a8944423543485a"
     cluster="m2321.5a8944423543485a"
     cluster_size="15"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['0508f9dd8258073c1f69a938a98cf3fd','0983f67e1ca17f29146b63ebb53122a2','f0d6ff97181116e79ff0946e46d6ebc6']"

   strings:
      $hex_string = { e3df1ca9f116ae3e3d41b85e4a798e09fea82c8f0dc3cb66d30fd6b64b4672bd08f64f5047bcd89f98eb2d80831e62f70b1ddef4c742337687e9c8386835d5e0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
