
rule m2377_211e6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.211e6a48c0000b12"
     cluster="m2377.211e6a48c0000b12"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html redirector"
     md5_hashes="['0bb3f7eb84188fdde45c763ac35dd655','0fd764d1e5a1f3a803e8e86a95a1194c','b42819e33c2591448f4bfb8899a02bf9']"

   strings:
      $hex_string = { 3336297d3b6966282127272e7265706c616365282f5e2f2c537472696e6729297b7768696c6528632d2d297b645b632e746f537472696e672861295d3d6b5b63 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
