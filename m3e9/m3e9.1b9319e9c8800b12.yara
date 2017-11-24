
rule m3e9_1b9319e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1b9319e9c8800b12"
     cluster="m3e9.1b9319e9c8800b12"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['1856fff05ae59302a102e6bca29de61f','245f80c339ef4e319b49cb98d040dea9','d96d4b1c52bdb1b8b3e5109110e3db95']"

   strings:
      $hex_string = { 1ef103794a9ef38ae0070fa6c877e765c017fb725baa62e496d87d917a6568eb155fd6bd955849f6d2054192ba4e7359388475711074b7a476ff6ab1189cd053 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
