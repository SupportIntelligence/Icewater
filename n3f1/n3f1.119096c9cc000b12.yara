
rule n3f1_119096c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.119096c9cc000b12"
     cluster="n3f1.119096c9cc000b12"
     cluster_size="3"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="opfake androidos fakeinst"
     md5_hashes="['6c0d8895b618ef2f21d9f126a9bd0e1a','db0a69e665e36c18d049d4d6db2d1dbd','fd5a82fa210838d757ce11be0854efdb']"

   strings:
      $hex_string = { 25ce6d91133ed90fbf6e41cb207cd5aa861f0b0de87e5e0e421bf814cd16e1d1fd72194be2a490bb79e453ca367f7628f5d25cb8a3f79510264e402db7344c9f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
