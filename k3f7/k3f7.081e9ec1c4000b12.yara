
rule k3f7_081e9ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.081e9ec1c4000b12"
     cluster="k3f7.081e9ec1c4000b12"
     cluster_size="61"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker html"
     md5_hashes="['0142664042ad9d84a63ed83716533eba','050a52cf02bb366184e7b299b5dd08e5','25418afa05cdbe430845c1a9363d2e3a']"

   strings:
      $hex_string = { 643a4458496d6167655472616e73666f726d2e4d6963726f736f66742e416c706861284f7061636974793d3029273b20206d617267696e2d6c6566743a202d35 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
