
rule m2319_4b1b1ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.4b1b1ec1c8000b12"
     cluster="m2319.4b1b1ec1c8000b12"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['6122a525228021d320a921e180e6da84','6831d7fc91af224cefdb17cbf1829e06','ffca46ba0187ab01b79139bbbbf8402f']"

   strings:
      $hex_string = { 643a4458496d6167655472616e73666f726d2e4d6963726f736f66742e416c706861284f7061636974793d3029262333393b3b20206d617267696e2d6c656674 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
