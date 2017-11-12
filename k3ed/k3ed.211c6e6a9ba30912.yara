
rule k3ed_211c6e6a9ba30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.211c6e6a9ba30912"
     cluster="k3ed.211c6e6a9ba30912"
     cluster_size="396"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy malicious attribute"
     md5_hashes="['02afa8a55881f97f11731080a9afdced','03e39fa14d51ebd6b2215c91b9bd5149','0a48b0d0dcf6bf956955152a9f5159c9']"

   strings:
      $hex_string = { 1003000000278300100200000033830010020000003c83001006000000488300100600000051830010060000005d830010060000006983001006000000758300 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
