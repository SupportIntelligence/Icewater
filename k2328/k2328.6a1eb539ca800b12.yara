
rule k2328_6a1eb539ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2328.6a1eb539ca800b12"
     cluster="k2328.6a1eb539ca800b12"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hidelink html clickjack"
     md5_hashes="['b4c5096712f1bdc5f5b8dbbb3e769cdac329d0d6','eae07c99282b874629d18500e7b106a68ab596af','0d1d89107a27409d6bf8bafe5b091f1513f2b3c3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2328.6a1eb539ca800b12"

   strings:
      $hex_string = { 6b5f637a78563164763155546645726451793332202d2d3e3c73637269707420747970653d22746578742f6a617661736372697074223e646f63756d656e742e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
