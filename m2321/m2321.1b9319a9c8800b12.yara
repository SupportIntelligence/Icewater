
rule m2321_1b9319a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1b9319a9c8800b12"
     cluster="m2321.1b9319a9c8800b12"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['286d4be85219cc6615e92faaf2acc209','3937532c1d6f1ffeb48526bdf9442460','ce2e892707304a3fe3a4a93efba67c7c']"

   strings:
      $hex_string = { 1ef103794a9ef38ae0070fa6c877e765c017fb725baa62e496d87d917a6568eb155fd6bd955849f6d2054192ba4e7359388475711074b7a476ff6ab1189cd053 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
