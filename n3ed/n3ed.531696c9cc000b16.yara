
rule n3ed_531696c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.531696c9cc000b16"
     cluster="n3ed.531696c9cc000b16"
     cluster_size="234"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['017904b3d51e8357af04022a5d90125d','0472d81352364dfc3cf2ac89fd5e08e8','3e2cccc6751c85502f4d4920aeaba870']"

   strings:
      $hex_string = { 53560fb7710633d285f6578d440818761e8b7c24148b480c3bf972098b580803d93bfb720c83c20183c0283bd672e633c05f5e5bc36a0868101c0210e8eafdff }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
