
rule n2800_531a948cbaa90912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2800.531a948cbaa90912"
     cluster="n2800.531a948cbaa90912"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mikey malicious neoreklami"
     md5_hashes="['040832a8ff1fb210db702cc323e582539eb83ce9','7b7f2e6e15d9e7158343ed913f28cc0fc446d5f7','1e43f9f0f863b8ff246d3967021004a5bf855394']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2800.531a948cbaa90912"

   strings:
      $hex_string = { fa772448395118741e41b001e85c26ffff84c0741248837b181048897b107203488b1bc6043b00488b5c24304883c4205fc3cccccc894c240856574881ec2801 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
