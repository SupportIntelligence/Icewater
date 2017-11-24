
rule m2319_199d1ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.199d1ec1c8000b12"
     cluster="m2319.199d1ec1c8000b12"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker clicker"
     md5_hashes="['93962473b47d4219b43a3a55495281b2','de937fe9ca6ade47ed95cec7ba1ee4a9','f5bf2f43da2507de4cd1cc6cf382a249']"

   strings:
      $hex_string = { 307877376b6269716f7679222c2022623468222c20226c6566742d6d6964646c65225d293b0a2866756e6374696f6e2829207b76617220733d646f63756d656e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
