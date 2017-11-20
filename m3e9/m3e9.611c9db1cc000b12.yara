
rule m3e9_611c9db1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c9db1cc000b12"
     cluster="m3e9.611c9db1cc000b12"
     cluster_size="1438"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['004f6c3a13e95cc0830e266922491f62','00fc29da0be02fa03a3a1bba11c4f9f9','07e6267ef0a1d3063175960f39885e58']"

   strings:
      $hex_string = { 42f4a90c4cbc2f3fe5229f554bb2bd707c3a97f9665ddf9284eb8e95445b07f8ea11b5617840e930016888791426ef7441620239bc8c80ad63b628daa2c34e50 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
