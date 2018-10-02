
rule n26d5_5d322926cdbbb912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.5d322926cdbbb912"
     cluster="n26d5.5d322926cdbbb912"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious gifq"
     md5_hashes="['564886a88602dc5301771ffd244c32508210b8e4','4036f025df44c3b16d42bfc40e19123c055c544e','085e51cc79503907b41d515790bcc3d591ecf5c0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.5d322926cdbbb912"

   strings:
      $hex_string = { dbc5076fff44d4e3df36d5d790b0e0c28b263c96a269708ed07cb21c497785803977b94ec05ab6f2b77afb6d09355f601af0c70d4dcd6eabf1e9f62304a9e243 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
