
rule n26bb_2b9c949dca220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.2b9c949dca220b12"
     cluster="n26bb.2b9c949dca220b12"
     cluster_size="80"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="incredimail malicious perion"
     md5_hashes="['3c864242222ef21b9a873db5de63a65953a3cff4','844ee8f5119d103b77269db4de979b45d377513e','50ce6d8c106eec3816d31c91c69339d6a2906749']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.2b9c949dca220b12"

   strings:
      $hex_string = { 6d1d3ded41650a53dd160fa1cd8e2a015282fdd260f63ed7e6a7fb9058f5aa4a42514e30271839bb34741bf98b724498471992052be8753815b368995ec797ea }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
