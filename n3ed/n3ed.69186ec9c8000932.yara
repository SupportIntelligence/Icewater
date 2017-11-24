
rule n3ed_69186ec9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.69186ec9c8000932"
     cluster="n3ed.69186ec9c8000932"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy malicious stantinko"
     md5_hashes="['01ba4030353bb3f140c5378983f4be2a','198959e761685ea3e8e1a5c0bace23f7','abb3626bdde8fbbdcd458331c06a06b9']"

   strings:
      $hex_string = { 4dfc5f5e6689480a5bc9c3ccff25fc9004108bff558bec837d0c007406c6012d41f7d8568bf133d2f7750883fa09760580c257eb0380c23088114185c075e788 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
