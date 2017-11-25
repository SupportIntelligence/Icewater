
rule m2319_2b9343028a056d16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b9343028a056d16"
     cluster="m2319.2b9343028a056d16"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['049cf7050311b502b41b74fccd308a31','298826d083cc59d9b609d4261fc310cf','d0f67507b7dbc123b8d100cd27d19a13']"

   strings:
      $hex_string = { 6e65772d6175746f6d6f746976652e626c6f6773706f742e64652f7365617263682f6c6162656c2f494d475f30393431273e494d475f303934313c2f613e0a3c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
