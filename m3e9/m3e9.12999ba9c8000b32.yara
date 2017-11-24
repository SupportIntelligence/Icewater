
rule m3e9_12999ba9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.12999ba9c8000b32"
     cluster="m3e9.12999ba9c8000b32"
     cluster_size="48"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0ef76b6799885512efc7bc9cad096588','10eb3ff7065b9f78a7c294ffd56a3d31','a7e71bc4f918fabcca84820a42b37a95']"

   strings:
      $hex_string = { 00598945ec8365fc0085c0741f68d9a800016847520001578d58046a0c538938e82c5600008bc38b5d08eb0233c0834dfcff33ff397e18894614897df00f8e88 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
