
rule k2319_69161ce9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.69161ce9c8800b12"
     cluster="k2319.69161ce9c8800b12"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['146eca97052c1b492515e79e1a89650e7edc7b79','790ee35be46e7ba3ba2d40229d80ea5089738895','3accdc46d6cbed724ab7ed643f4111c351104867']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.69161ce9c8800b12"

   strings:
      $hex_string = { 4d223a28362e313945322c322e34394532292929627265616b7d3b76617220673951353d7b274e3979273a2249222c277a35273a66756e6374696f6e28422c71 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
