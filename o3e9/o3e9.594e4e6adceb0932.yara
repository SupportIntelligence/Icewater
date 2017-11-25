
rule o3e9_594e4e6adceb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.594e4e6adceb0932"
     cluster="o3e9.594e4e6adceb0932"
     cluster_size="100"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['001edd1897f4a510be0b96b0122a1abe','00286a1e2b0b4160cce302dc0a4dd7f1','34cc8507eb52139556e2369e9933864e']"

   strings:
      $hex_string = { 006f002000260041006c006c000600260043006c006f0073006500040042006b005300700003005400610062000300450073006300050045006e007400650072 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
