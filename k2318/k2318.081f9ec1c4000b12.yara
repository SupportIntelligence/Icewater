
rule k2318_081f9ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.081f9ec1c4000b12"
     cluster="k2318.081f9ec1c4000b12"
     cluster_size="57"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker html"
     md5_hashes="['11a8f5126b90f3b4a03a71de84f0c5f0','1373f13ad16856d65e92495b282d848d','5b02d853261080b9a6e1950b25e8507a']"

   strings:
      $hex_string = { 643a4458496d6167655472616e73666f726d2e4d6963726f736f66742e416c706861284f7061636974793d3029273b20206d617267696e2d6c6566743a202d35 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
