
rule k2321_0ac88a5c9e6a48ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0ac88a5c9e6a48ba"
     cluster="k2321.0ac88a5c9e6a48ba"
     cluster_size="14"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['0467dc9a3a646f1460c6487719855797','07bb34a83c96f10e8df8f9e519334048','fbc744793d0ba0d36a4f27609693e045']"

   strings:
      $hex_string = { 6b867931abbd5924e0bb284f091fb67433c6297c582e00a119414065a0445bacd30d5e6deca678af6c1b7d21f9f594fea32ac70eed8903a9ad277162738ea8c9 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
