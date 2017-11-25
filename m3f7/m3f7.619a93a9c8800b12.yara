
rule m3f7_619a93a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.619a93a9c8800b12"
     cluster="m3f7.619a93a9c8800b12"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker clicker"
     md5_hashes="['4e6999392b3f0d5f999859cbcf24d888','625864d339b9ae7197eddb9edba161f0','9298a71ecef84176e60af67fa6cb419c']"

   strings:
      $hex_string = { 234431443744463b6261636b67726f756e642d636f6c6f723a234635463646393b6d617267696e3a307078206175746f3b223e3c6469762069643d226e657477 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
