
rule m926_4b1a84d2dd1af113
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m926.4b1a84d2dd1af113"
     cluster="m926.4b1a84d2dd1af113"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mackeeper unwanted enqqce"
     md5_hashes="['1cbd54e32fe2d8b76723735efd73be3a91a1800c','cd5f359863c1d1cc97a361f4b76693f2cb98a0b8','3ac2de656e9b0c96ec347c01f6db9fc66f96f257']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m926.4b1a84d2dd1af113"

   strings:
      $hex_string = { 2538ac1e5280a34d43d6a289ca22f3bc70b7ccc3121c9361190440ea2859e47f781a0777af31cecd630698be79966e5d233d8a17c80aff7a20536ca87d58f654 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
