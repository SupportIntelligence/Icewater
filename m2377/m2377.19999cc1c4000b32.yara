
rule m2377_19999cc1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.19999cc1c4000b32"
     cluster="m2377.19999cc1c4000b32"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['14ae72a3001662e43c4c6103fe2b1e64','8f5965b6cc2b971094539fc0d83db5d7','b5a36843ba63d0567dcc41974c6e947c']"

   strings:
      $hex_string = { 643a4458496d6167655472616e73666f726d2e4d6963726f736f66742e416c706861284f7061636974793d3029262333393b3b20206d617267696e2d6c656674 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
