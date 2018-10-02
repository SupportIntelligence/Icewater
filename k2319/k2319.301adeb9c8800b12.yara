
rule k2319_301adeb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.301adeb9c8800b12"
     cluster="k2319.301adeb9c8800b12"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem multiplug"
     md5_hashes="['2af40f8d30bd9d72b031621dfc235199788a4145','76639a3d925bb239cbabd74d191980476f636734','87db07552db41437a7c0c450d9fa3e9a099e5c29']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.301adeb9c8800b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20475b4e5d3b7d76617220503d28283132372c38322e354531293c3d2831342e343345322c39312e293f283130332e2c226822 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
