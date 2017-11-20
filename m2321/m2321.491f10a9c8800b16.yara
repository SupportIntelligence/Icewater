
rule m2321_491f10a9c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.491f10a9c8800b16"
     cluster="m2321.491f10a9c8800b16"
     cluster_size="65"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys kryptik razy"
     md5_hashes="['02ff08b11acb47c9282df242bb38df7f','0e5859893b11cb195db3aaa298ee44cf','50f7c3dbbcb8ea30b9263d120b6ae207']"

   strings:
      $hex_string = { 4c6b8caded825af8affde58beb9bdcbaff29d8bc779d6fda926e831ca201c8d00a0eae3f2abe1921b286250012992091288d4724b35e7a8aeea511134440943d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
