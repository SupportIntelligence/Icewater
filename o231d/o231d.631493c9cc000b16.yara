
rule o231d_631493c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o231d.631493c9cc000b16"
     cluster="o231d.631493c9cc000b16"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp riskware clicker"
     md5_hashes="['64ccdd370006521b725e507af1ece84504b9733f','1b7d55ab7311ff8406989f8cfc72d8049791b706','cebe2a5707780a71db63dd0358ca627d40072a54']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o231d.631493c9cc000b16"

   strings:
      $hex_string = { c7bb55df05712632807ee87ffcf9e75fee8ffffad7cffbc39c6b1d099a11ec74381cf7876549e6402d776c068d4870be150342124130d054103c90985ad6ea4d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
