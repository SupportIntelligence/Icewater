
rule n26bb_5114e90bda631b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.5114e90bda631b32"
     cluster="n26bb.5114e90bda631b32"
     cluster_size="39"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy filerepmalware arkei"
     md5_hashes="['367ddae32da8c50a8038f1e7f00181a58ec8f794','839b66263b24292e0e4a32ae35f294b80a461295','ff14a3662ed65f67b6335f12013b6fcb11707a8d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.5114e90bda631b32"

   strings:
      $hex_string = { f00fb7044b6685c0790533c040eb089803c00fb644c60e03d0413bcf7ce38b75f88bc2c1e0026a0050e8ae6ffdff59595f668946305e5bc9c3558bec83ec2c53 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
