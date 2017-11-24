
rule k2321_1310cd72d7a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.1310cd72d7a30912"
     cluster="k2321.1310cd72d7a30912"
     cluster_size="16"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hupigon backdoor razy"
     md5_hashes="['04c5fe107a568fd1a3d060ad560e95e4','112a7f61ed182e4e2d244f15cd686acc','fffdec02bb6baac25ac7e7b2bb441ee7']"

   strings:
      $hex_string = { 979e7fcf6e6673f5c9f137a6b62a53549fcd44dde98eadafba10b379884860b9eda326d6335c7e2f99dc49f968d47cec050a4c0314a91c969471311952d71b90 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
