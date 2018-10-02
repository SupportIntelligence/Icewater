
rule n3f8_69985a18de430b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.69985a18de430b12"
     cluster="n3f8.69985a18de430b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos genbl olympus"
     md5_hashes="['af9eebc89a4da197d305cf4bc1e6c4142e8f8b81','673fc9db41ef06f48b159688ad7b5a67825ec0b9','37ff47a14c1fe5f8e94fdb35b0b68cb25ad4a3a0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.69985a18de430b12"

   strings:
      $hex_string = { 682b6c3866394736545131704e440a6463774143734472566a4650616230772b4e316a6565762f6b2b626435594c784561513348745a766d674f58424c2b6b52 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
