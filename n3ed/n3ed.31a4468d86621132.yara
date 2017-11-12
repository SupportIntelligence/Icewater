
rule n3ed_31a4468d86621132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a4468d86621132"
     cluster="n3ed.31a4468d86621132"
     cluster_size="228"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['01ad5a1889942a97f16198f682bb0f1a','02067a48c86d12e58c0a894cdf5b5b47','294ccc16cae839dd7c85d2b8878d2479']"

   strings:
      $hex_string = { 1100ff08b001eb232bc203c02bf23bc67d178d0c510fb714410fb75c4102c1e2100bd340891740ebb632c05f5e5b5dc38a4424048ac880e96180f919770204e0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
