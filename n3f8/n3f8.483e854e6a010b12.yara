
rule n3f8_483e854e6a010b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.483e854e6a010b12"
     cluster="n3f8.483e854e6a010b12"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="sandr androidos kasandra"
     md5_hashes="['fcea65d31b296dbc7d78ec252e674a3a68e6195f','e4853564673db29c4bd3561d58b99430fe1183df','db4a218fbbd83e9ef5d7800da1d70232267165f8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.483e854e6a010b12"

   strings:
      $hex_string = { e30307000a04b1431504b4426e20900048006e10e60307000a047b4482445275a7011506803fc6657f558226c8656e3094004805547485016e30f30834025472 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
