
rule n3f1_359916c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.359916c9cc000b12"
     cluster="n3f1.359916c9cc000b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="opfake androidos smssend"
     md5_hashes="['0f7d0f658b0c3167a2275ac0ba102c53','29c4b5ff7f15b3efce13b0025ef1d324','ff1ec1c3e09b967e22034579ed03c9b9']"

   strings:
      $hex_string = { 25ce6d91133ed90fbf6e41cb207cd5aa861f0b0de87e5e0e421bf814cd16e1d1fd72194be2a490bb79e453ca367f7628f5d25cb8a3f79510264e402db7344c9f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
