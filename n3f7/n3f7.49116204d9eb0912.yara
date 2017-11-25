
rule n3f7_49116204d9eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.49116204d9eb0912"
     cluster="n3f7.49116204d9eb0912"
     cluster_size="9"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['11a6be786bae855564dea78f15505aa4','254dd6b7e09adc405029ccc2fc397a68','d11058bd1a517a9498fee242ae174b94']"

   strings:
      $hex_string = { 546865206b696e67262333393b7320537065656368205b5354565d2e4456445269702e587669443c2f613e0a3c7370616e206469723d276c7472273e2832293c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
