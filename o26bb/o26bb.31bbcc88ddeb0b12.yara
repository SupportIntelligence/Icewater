
rule o26bb_31bbcc88ddeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.31bbcc88ddeb0b12"
     cluster="o26bb.31bbcc88ddeb0b12"
     cluster_size="1517"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy adload rdrv"
     md5_hashes="['67990415894cd813aeae2adc3188aade07c89087','1bd5227357fde5ea421b96653604489b1da6bae7','463356b256267dc9131f620cf56d0b2b7bc08fff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.31bbcc88ddeb0b12"

   strings:
      $hex_string = { c40c85d2741985f6740f8bca2bcf8a078804394783ee0175f55f8bc25e5dc3e89692f8ffcc6a14b83e885400e8049a020033db8d4dec53e8e48602008b3d4c5b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
