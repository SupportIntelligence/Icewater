
rule m3f7_619a11e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.619a11e9c8800b12"
     cluster="m3f7.619a11e9c8800b12"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker html"
     md5_hashes="['22c168e9e814c10dfb659cc0d3db8ffd','23e8a0a036e1503aaae3812ef12c1c3a','cd40177ed7564f7dc4ff04f1e66ad37a']"

   strings:
      $hex_string = { 234431443744463b6261636b67726f756e642d636f6c6f723a234635463646393b6d617267696e3a307078206175746f3b223e3c6469762069643d226e657477 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
