
rule k3f7_489f9ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.489f9ec1c4000b12"
     cluster="k3f7.489f9ec1c4000b12"
     cluster_size="51"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['062f564a2d3d5226c8c95ac0536756d7','08c1eab66ab8fbe8cd4ad890aa19924d','3b5ff294c91979093e151aaba68201b8']"

   strings:
      $hex_string = { 643a4458496d6167655472616e73666f726d2e4d6963726f736f66742e416c706861284f7061636974793d3029273b20206d617267696e2d6c6566743a202d35 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
