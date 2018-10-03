
rule o26c0_5b1aac09da9b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.5b1aac09da9b1912"
     cluster="o26c0.5b1aac09da9b1912"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor downloadhelper malicious"
     md5_hashes="['bd2ceafa64e93a1e97f2959321901972d8b037fb','d6ae72b16db51634f006ba5071d4b9e0431c2fe9','26a989372a78f014dce1a124a0c303a6f4143786']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.5b1aac09da9b1912"

   strings:
      $hex_string = { 32524453974e63dc88d92b2e7202ff0e3d00ec27612f2d8198b36ec87c7f07e542fcbc8ca1fe5551c5d29e18680fd8b96ccd7a00ab824fd5791904244c4b0df8 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
