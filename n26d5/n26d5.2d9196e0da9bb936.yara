
rule n26d5_2d9196e0da9bb936
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2d9196e0da9bb936"
     cluster="n26d5.2d9196e0da9bb936"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['4b0c39d198f573ff8948a4cd40fd955bcb6bb3b6','0cfa345e62f9e2dd1ca724aead7add2e73540f61','3569c57f8440342fd90dcddeb8be925fa1e65e93']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2d9196e0da9bb936"

   strings:
      $hex_string = { dbc5076fff44d4e3df36d5d790b0e0c28b263c96a269708ed07cb21c497785803977b94ec05ab6f2b77afb6d09355f601af0c70d4dcd6eabf1e9f62304a9e243 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
