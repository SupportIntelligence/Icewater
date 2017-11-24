
rule p3f7_3912d19cea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3f7.3912d19cea210912"
     cluster="p3f7.3912d19cea210912"
     cluster_size="20"
     filetype = "ASCII text"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos triada ransomkd"
     md5_hashes="['10833c9178e416e0e238c80659004242','3196dcefe2054765239c4dff1cbd967c','c48cfd64e21b9ae3f972ed2877a11f6b']"

   strings:
      $hex_string = { 6a08a9a3f5e8f7baeab246cb84a601c1234abb39d52c9e05cae62553d27cc6f32a798ed7c8e3be8a0cfedd209f7837f85982192bcdedaad9ecd4d86b40d0477f }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
