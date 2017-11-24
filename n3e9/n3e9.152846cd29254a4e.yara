
rule n3e9_152846cd29254a4e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.152846cd29254a4e"
     cluster="n3e9.152846cd29254a4e"
     cluster_size="196"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod nimda deepscan"
     md5_hashes="['018bd384afba986392b8096e5cc0d9c1','053b4ee3b1d31f9f17fe27a2f3ef895b','169f73006dee0f9dc931b1f7a8444e56']"

   strings:
      $hex_string = { cc2c8b19cf7ffcbe5f52a9cabdf7b9c99f54e54b65aab6d6d168cdf4eceedd3dadf35530c504eb08af2282141c4628fbf60f15038a43d36f44c8817a8835ba21 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
